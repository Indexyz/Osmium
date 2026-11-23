package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Store is the object storage behind uploaded segments. Names use "/" as
// separator and are relative to the store's prefix.
type Store interface {
	Put(ctx context.Context, name string, data []byte) error
	// Get returns an error wrapping fs.ErrNotExist for a missing object.
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	// List returns the entries directly under dir ("" or ending in "/"),
	// relative to dir; sub-directories end in "/".
	List(ctx context.Context, dir string) ([]string, error)
	Delete(ctx context.Context, names []string) error
}

// S3Config configures an S3-compatible store (AWS S3, MinIO, RustFS).
type S3Config struct {
	// Endpoint is a URL such as https://minio.example.com:9000.
	Endpoint string
	Bucket   string
	Prefix   string
	Region   string
	// AccessKeyID and SecretAccessKey are static credentials. When empty,
	// the AWS_* / MINIO_* environment variables and then IAM are used.
	AccessKeyID     string
	SecretAccessKey string
	// CAFile adds a PEM CA bundle for a privately signed endpoint.
	CAFile string
}

type s3Store struct {
	c      *minio.Client
	bucket string
	prefix string
}

// NewS3 connects to an S3-compatible endpoint and checks the bucket exists.
// Path-style addressing is used except for AWS hosts, as MinIO and RustFS
// expect by default.
func NewS3(ctx context.Context, cfg S3Config) (Store, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("audit: s3 endpoint must be http(s)://host[:port], got %q", cfg.Endpoint)
	}
	if cfg.Bucket == "" {
		return nil, errors.New("audit: s3 bucket is required")
	}
	creds := credentials.NewChainCredentials([]credentials.Provider{&credentials.EnvAWS{}, &credentials.EnvMinio{}, &credentials.IAM{}})
	if cfg.AccessKeyID != "" {
		creds = credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, "")
	}
	opts := &minio.Options{Creds: creds, Secure: u.Scheme == "https", Region: cfg.Region, BucketLookup: minio.BucketLookupAuto}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("audit: no certificates in %s", cfg.CAFile)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		opts.Transport = tr
	}
	c, err := minio.New(u.Host, opts)
	if err != nil {
		return nil, fmt.Errorf("audit: s3: %w", err)
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ok, err := c.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("audit: s3 bucket %q: %w", cfg.Bucket, err)
	}
	if !ok {
		return nil, fmt.Errorf("audit: s3 bucket %q does not exist", cfg.Bucket)
	}
	return &s3Store{c: c, bucket: cfg.Bucket, prefix: prefix}, nil
}

func (s *s3Store) Put(ctx context.Context, name string, data []byte) error {
	_, err := s.c.PutObject(ctx, s.bucket, s.prefix+name, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/gzip", DisableMultipart: true})
	return err
}

func (s *s3Store) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	obj, err := s.c.GetObject(ctx, s.bucket, s.prefix+name, minio.GetObjectOptions{})
	if err == nil {
		_, err = obj.Stat() // GetObject is lazy; surface a missing key here
	}
	if err != nil {
		if obj != nil {
			_ = obj.Close()
		}
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("%s: %w", name, fs.ErrNotExist)
		}
		return nil, err
	}
	return obj, nil
}

func (s *s3Store) List(ctx context.Context, dir string) ([]string, error) {
	base := s.prefix + dir
	var out []string
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: base}) {
		if o.Err != nil {
			return nil, o.Err
		}
		out = append(out, strings.TrimPrefix(o.Key, base))
	}
	return out, nil
}

func (s *s3Store) Delete(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	objs := make(chan minio.ObjectInfo, len(names))
	for _, n := range names {
		objs <- minio.ObjectInfo{Key: s.prefix + n}
	}
	close(objs)
	var errs []error
	for r := range s.c.RemoveObjects(ctx, s.bucket, objs, minio.RemoveObjectsOptions{}) {
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.ObjectName, r.Err))
		}
	}
	return errors.Join(errs...)
}
