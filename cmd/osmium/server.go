package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/config"
	"github.com/indexyz/osmium/internal/server"
	"github.com/indexyz/osmium/internal/sessions"
	"github.com/indexyz/osmium/internal/storage"
)

func newServerCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "server",
		Short: "运行 Server（Web API、SSH Gateway、Agent 管理）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServer(cfgPath, newLogger())
		},
	}
	c.Flags().StringVarP(&cfgPath, "config", "c", "server.json", "Server 配置文件")
	return c
}

func openAudit(ctx context.Context, cfg *config.Server, db *storage.SQLiteStore, log *slog.Logger) (*audit.Logger, error) {
	ac := audit.Config{
		Dir:       cfg.Audit.Dir,
		ServerID:  cfg.ServerID,
		Retention: cfg.Audit.Retention.D(),
		OnError:   func(err error) { log.Error("audit", "err", err) },
	}
	if cfg.Audit.Stdout {
		ac.Mirror = os.Stdout
	}
	if db != nil {
		ac.OnBatch = db.InsertAuditBatch
		if cfg.Audit.S3 == nil {
			// When not merging remote S3 segments from other replicas, serve
			// admin audit queries directly from the indexed local SQLite table.
			ac.SearchIndex = db.SearchAudit
		}
	}
	if s := cfg.Audit.S3; s != nil {
		sc := audit.S3Config{Endpoint: s.Endpoint, Bucket: s.Bucket, Prefix: s.Prefix, Region: s.Region, AccessKeyID: s.AccessKeyID, CAFile: s.CAFile}
		if s.SecretAccessKeyFile != "" {
			b, err := os.ReadFile(s.SecretAccessKeyFile)
			if err != nil {
				return nil, err
			}
			sc.SecretAccessKey = strings.TrimSpace(string(b))
		}
		store, err := audit.NewS3(ctx, sc)
		if err != nil {
			return nil, err
		}
		ac.Store, ac.SegmentInterval, ac.SegmentMaxBytes = store, s.SegmentInterval.D(), s.SegmentMaxBytes
		log.Info("audit: uploading to s3", "endpoint", s.Endpoint, "bucket", s.Bucket, "prefix", s.Prefix)
	}
	return audit.Open(ac)
}

func readUserCAKeys(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("ca.user_ca_public_key_file is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

func loadInitialPolicy(cfg *config.Server, db *storage.SQLiteStore, log *slog.Logger) (*authz.Snapshot, error) {
	if db != nil {
		doc, ok, err := db.LoadDocument()
		if err != nil {
			return nil, fmt.Errorf("load state_db policy: %w", err)
		}
		if ok {
			snap, err := authz.Build(doc)
			if err != nil {
				return nil, fmt.Errorf("build state_db policy: %w", err)
			}
			log.Info("loaded policy from state_db", "hosts", snap.HostCount(), "host_cas", len(snap.HostCAs()))
			return snap, nil
		}
		if cfg.PolicyFile != "" {
			snap, err := authz.LoadFile(cfg.PolicyFile)
			if err != nil {
				return nil, err
			}
			if err := db.SaveDocument(snap.Document()); err != nil {
				return nil, fmt.Errorf("bootstrap state_db from policy_file: %w", err)
			}
			log.Info("bootstrapped state_db from policy_file", "policy_file", cfg.PolicyFile, "hosts", snap.HostCount())
			return snap, nil
		}
		// Empty state_db without policy_file: start with an empty default scope.
		snap, err := authz.Build(authz.Document{Scope: "default"})
		if err != nil {
			return nil, err
		}
		if err := db.SaveDocument(snap.Document()); err != nil {
			return nil, err
		}
		return snap, nil
	}
	return authz.LoadFile(cfg.PolicyFile)
}

func runServer(cfgPath string, log *slog.Logger) error {
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var db *storage.SQLiteStore
	if cfg.StateDB != "" {
		db, err = storage.OpenSQLite(cfg.StateDB)
		if err != nil {
			return err
		}
		defer func() {
			if err := db.Close(); err != nil {
				log.Error("state_db close failed", "err", err)
			}
		}()
		log.Info("state_db opened (SQLite WAL)", "path", cfg.StateDB)
	}

	snap, err := loadInitialPolicy(cfg, db, log)
	if err != nil {
		return err
	}
	store := authz.NewStore(snap)
	if db != nil {
		store.SetPersister(db)
	}

	aud, err := openAudit(ctx, cfg, db, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := aud.Close(); err != nil {
			log.Error("audit: final upload failed; segments stay on disk for the next start", "err", err)
		}
	}()

	caKeys, err := readUserCAKeys(cfg.CA.UserCAPublicKeyFile)
	if err != nil {
		return err
	}
	signer, err := ca.NewStepCA(ca.StepConfig{
		URL: cfg.CA.URL, RootCAFile: cfg.CA.RootCAFile, ProvisionerName: cfg.CA.ProvisionerName,
		JWKFile: cfg.CA.JWKFile, JWKPasswordFile: cfg.CA.JWKPasswordFile, Audience: cfg.CA.Audience,
		SignPath: cfg.CA.SignPath, ValidBefore: cfg.CA.ValidBefore, Timeout: cfg.CA.Timeout.D(),
		UserCAPublicKeys: caKeys, MaxLifetime: cfg.CA.MaxCertLifetime.D(), AllowedExts: cfg.CA.AllowedExtensions,
		RequiredSourceAddress: cfg.CA.RequiredSourceAddress,
	})
	if err != nil {
		return err
	}

	var directIssuer *server.DirectCertIssuer
	if cfg.DirectCA != nil {
		directIssuer, err = buildDirectIssuer(cfg, caKeys)
		if err != nil {
			return err
		}
		log.Info("direct SSH certificate issuance enabled",
			"source_address_mode", cfg.DirectCA.SourceAddressMode,
			"default_role_ttl", cfg.DirectCA.DefaultRoleTTL.D(),
			"max_role_ttl", cfg.DirectCA.MaxRoleTTL.D(),
		)
	} else if doc := snap.Document(); len(doc.CertRoles) > 0 || hasDirectHost(doc.Hosts) {
		log.Warn("policy defines direct hosts or cert_roles, but direct_ca is not configured; POST /api/v1/direct-certs will stay disabled")
	}

	hub := agenthub.New(agenthub.Config{
		ServerID:          cfg.ServerID,
		Mux:               cfg.Smux.Mux(),
		PingInterval:      cfg.PingInterval.D(),
		HeartbeatTimeout:  cfg.HeartbeatTimeout.D(),
		MuxIdleTTL:        cfg.MuxIdleTTL.D(),
		StreamOpen:        cfg.StreamOpen.D(),
		MaxStreams:        cfg.MaxStreams,
		MaxPendingStreams: cfg.MaxPendingStreams,
		AcceptRate:        cfg.AgentAcceptRate,
		AcceptBurst:       cfg.AgentAcceptBurst,
	}, store, aud, log)
	store.OnHostChange(func(snap *authz.Snapshot, agentIDs []string) {
		for _, id := range agentIDs {
			hub.ReconcileHost(snap, id)
		}
	})

	revoke := true
	if cfg.Sessions.RevokeActive != nil {
		revoke = *cfg.Sessions.RevokeActive
	}
	mgr := sessions.NewManager(sessions.Config{
		AttachTimeout: cfg.Sessions.AttachTimeout.D(), SSHHandshake: cfg.Sessions.SSHHandshake.D(),
		MaxSessionDuration: cfg.Sessions.MaxSessionDuration.D(), IdleTimeout: cfg.Sessions.IdleTimeout.D(),
		MaxPerUser: cfg.Sessions.MaxPerUser, MaxTotal: cfg.Sessions.MaxTotal,
		MaxConcurrentSigns: cfg.Sessions.MaxConcurrentSigns, RevokeActive: revoke,
	}, store, hub, signer, aud, log)
	defer mgr.Shutdown()

	pub, err := url.Parse(cfg.PublicURL)
	if err != nil || pub.Host == "" {
		return fmt.Errorf("invalid public_url")
	}
	secure := pub.Scheme == "https"
	if cfg.SecureCookie != nil {
		secure = *cfg.SecureCookie
	}
	var oidcCfg *authn.OIDCConfig
	if cfg.OIDC != nil {
		secret := ""
		if cfg.OIDC.ClientSecretFile != "" {
			b, err := os.ReadFile(cfg.OIDC.ClientSecretFile)
			if err != nil {
				return err
			}
			secret = strings.TrimSpace(string(b))
		}
		oidcCfg = &authn.OIDCConfig{Issuer: cfg.OIDC.Issuer, ClientID: cfg.OIDC.ClientID, ClientSecret: secret, RedirectURL: cfg.OIDC.RedirectURL, Scopes: cfg.OIDC.Scopes, GroupsClaim: cfg.OIDC.GroupsClaim}
	}
	if cfg.DevLogin {
		log.Warn("dev_login is enabled: anyone reaching the web listener can log in as any user. Never enable in production.")
	}
	var sessStore authn.SessionStore
	if db != nil {
		sessStore = db
	}
	auth, err := authn.New(ctx, authn.Config{
		OIDC: oidcCfg, DevLogin: cfg.DevLogin, SessionTTL: cfg.WebSession.D(), SecureCookie: secure, Store: sessStore,
	}, aud, log)
	if err != nil {
		return err
	}
	defer auth.Shutdown()

	store.OnChange(func(snap *authz.Snapshot) {
		webN, cliN := auth.RevokeMatching(snap.IsDisabled)
		if webN > 0 || cliN > 0 {
			log.Info("revoked credentials for disabled users after policy reload", "revision", snap.Revision, "web_sessions", webN, "cli_tokens", cliN)
			aud.Record(audit.Event{Actor: "system", Action: "policy.disable_revoke", Result: "ok", Revision: snap.Revision, Extra: map[string]any{"web_sessions": webN, "cli_tokens": cliN}})
		}
	})

	srv := &server.Server{Store: store, Hub: hub, Sessions: mgr, Direct: directIssuer, Auth: auth, Audit: aud, Log: log, AllowedOrigins: []string{pub.Scheme + "://" + pub.Host}}

	// SIGHUP reloads policy_file (when configured) and syncs to state_db.
	if cfg.PolicyFile != "" {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				s, err := authz.LoadFile(cfg.PolicyFile)
				if err != nil {
					log.Error("policy reload failed; keeping current revision", "err", err)
					continue
				}
				store.Replace(s)
				log.Info("policy reloaded", "revision", s.Revision, "hosts", s.HostCount())
			}
		}()
	}

	clientCAs, err := os.ReadFile(cfg.AgentClientCA)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAs) {
		return errors.New("agent_client_ca contains no certificates")
	}
	agentSrv := &http.Server{
		Addr:              cfg.AgentListen,
		Handler:           srv.AgentHandler(),
		TLSConfig:         &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	webSrv := &http.Server{Addr: cfg.Listen, Handler: srv.WebHandler(), ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- agentSrv.ListenAndServeTLS(cfg.AgentTLSCert, cfg.AgentTLSKey) }()
	go func() {
		if cfg.TLSCert != "" {
			errc <- webSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- webSrv.ListenAndServe()
		}
	}()
	log.Info("server started", "web", cfg.Listen, "agent", cfg.AgentListen, "policy_revision", store.Current().Revision)
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	// Drain Agent handlers first so disconnect audit events flush cleanly before
	// closing the audit logger and SQLite store.
	hub.Shutdown()
	hub.Wait(5 * time.Second)
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = webSrv.Shutdown(sctx)
	_ = agentSrv.Shutdown(sctx)
	return nil
}

func hasDirectHost(hosts []*authz.Host) bool {
	for _, h := range hosts {
		if h.AllowsDirect() {
			return true
		}
	}
	return false
}

func buildDirectIssuer(cfg *config.Server, fallbackCAKeys []string) (*server.DirectCertIssuer, error) {
	dc := cfg.DirectCA
	url := dc.URL
	if url == "" {
		url = cfg.CA.URL
	}
	rootCA := dc.RootCAFile
	if rootCA == "" {
		rootCA = cfg.CA.RootCAFile
	}
	prov := dc.ProvisionerName
	if prov == "" {
		prov = cfg.CA.ProvisionerName
	}
	jwkFile := dc.JWKFile
	jwkPass := dc.JWKPasswordFile
	if jwkFile == "" {
		jwkFile = cfg.CA.JWKFile
		jwkPass = cfg.CA.JWKPasswordFile
	}
	caKeys := fallbackCAKeys
	if dc.UserCAPublicKeyFile != "" {
		var err error
		caKeys, err = readUserCAKeys(dc.UserCAPublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("direct_ca: %w", err)
		}
	}
	maxRoleTTL := dc.MaxRoleTTL.D()
	if maxRoleTTL <= 0 {
		maxRoleTTL = 8 * time.Hour
	}
	maxLife := dc.MaxCertLifetime.D()
	if maxLife <= 0 {
		// Allow slight clock-skew headroom above server-capped role TTL.
		maxLife = maxRoleTTL + 30*time.Second
	}
	allowedExts := dc.AllowedExtensions
	if allowedExts == nil {
		allowedExts = []string{"permit-pty", "permit-user-rc", "permit-port-forwarding"}
	}
	reqSource := dc.RequiredSourceAddress
	if dc.SourceAddressMode == "static" && reqSource == "" {
		reqSource = dc.SourceAddressCIDRs
	}
	directSigner, err := ca.NewStepCA(ca.StepConfig{
		URL:                   url,
		RootCAFile:            rootCA,
		ProvisionerName:       prov,
		JWKFile:               jwkFile,
		JWKPasswordFile:       jwkPass,
		Audience:              dc.Audience,
		SignPath:              dc.SignPath,
		ValidBefore:           dc.ValidBefore,
		Timeout:               dc.Timeout.D(),
		UserCAPublicKeys:      caKeys,
		MaxLifetime:           maxLife,
		AllowedExts:           allowedExts,
		RequiredSourceAddress: reqSource,
	})
	if err != nil {
		return nil, fmt.Errorf("direct_ca: %w", err)
	}
	return server.NewDirectCertIssuer(directSigner, server.DirectCertConfig{
		DefaultHostTTL:     dc.DefaultHostTTL.D(),
		DefaultRoleTTL:     dc.DefaultRoleTTL.D(),
		MaxRoleTTL:         maxRoleTTL,
		SourceAddressMode:  dc.SourceAddressMode,
		SourceAddressCIDRs: dc.SourceAddressCIDRs,
		TrustedProxies:     dc.TrustedProxies,
		MaxConcurrentSigns: cfg.Sessions.MaxConcurrentSigns,
	})
}
