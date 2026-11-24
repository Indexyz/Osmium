package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/indexyz/osmium/internal/config"
)

// certReloader caches the Agent's mTLS client certificate pair and reloads it
// automatically whenever either file's modification time or size changes, so
// certificate rotation across large fleets needs no process restart.
type certReloader struct {
	certPath string
	keyPath  string
	log      *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	certTime time.Time
	certSize int64
	keyTime  time.Time
	keySize  int64
}

func newCertReloader(certPath, keyPath string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath, log: log}
	if _, err := r.reload(true); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.reload(false)
}

func (r *certReloader) reload(force bool) (*tls.Certificate, error) {
	cs, cerr := os.Stat(r.certPath)
	ks, kerr := os.Stat(r.keyPath)

	r.mu.Lock()
	defer r.mu.Unlock()
	if cerr != nil || kerr != nil {
		if r.cert != nil {
			if r.log != nil {
				r.log.Warn("agent mTLS cert stat failed; keeping cached certificate", "cert_err", cerr, "key_err", kerr)
			}
			return r.cert, nil
		}
		if cerr != nil {
			return nil, cerr
		}
		return nil, kerr
	}
	if !force && r.cert != nil &&
		cs.ModTime().Equal(r.certTime) && cs.Size() == r.certSize &&
		ks.ModTime().Equal(r.keyTime) && ks.Size() == r.keySize {
		return r.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		if r.cert != nil {
			if r.log != nil {
				r.log.Error("agent mTLS cert reload failed; keeping cached certificate", "err", err)
			}
			return r.cert, nil
		}
		return nil, err
	}
	r.cert = &pair
	r.certTime, r.certSize = cs.ModTime(), cs.Size()
	r.keyTime, r.keySize = ks.ModTime(), ks.Size()
	if !force && r.log != nil {
		r.log.Info("reloaded rotated agent mTLS client certificate")
	}
	return r.cert, nil
}

// RunConfig loads the Agent config file, builds the mTLS client config with
// hot certificate reload and runs until SIGINT/SIGTERM. Shared by `osmium agent`
// and the standalone osmium-agent binary.
func RunConfig(path, version string, log *slog.Logger) error {
	cfg, err := config.LoadAgent(path)
	if err != nil {
		return err
	}
	reloader, err := newCertReloader(cfg.ClientCert, cfg.ClientKey, log)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		GetClientCertificate: reloader.GetClientCertificate,
		MinVersion:           tls.VersionTLS12,
		ServerName:           cfg.ServerName,
	}
	if cfg.ServerCA != "" {
		pem, err := os.ReadFile(cfg.ServerCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("server_ca contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = Run(ctx, Options{
		ServerURL:       cfg.ServerURL,
		TLS:             tlsCfg,
		SSHTarget:       cfg.SSHTarget,
		Labels:          cfg.Labels,
		Version:         version,
		MaxStreams:      cfg.MaxStreams,
		Heartbeat:       cfg.Heartbeat.D(),
		StreamOpen:      cfg.StreamOpen.D(),
		TCPDial:         cfg.TCPDial.D(),
		RelayDrain:      cfg.RelayDrain.D(),
		ReconnectJitter: cfg.ReconnectJitter.D(),
		ReconnectMax:    cfg.ReconnectMax.D(),
		Mux:             cfg.Smux.Mux(),
		Log:             log,
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
