package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/config"
	"github.com/indexyz/osmium/internal/server"
	"github.com/indexyz/osmium/internal/sessions"
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

func runServer(cfgPath string, log *slog.Logger) error {
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	snap, err := authz.LoadFile(cfg.PolicyFile)
	if err != nil {
		return err
	}
	store := authz.NewStore(snap)
	aud := audit.New(os.Stdout)

	caKeys, err := readUserCAKeys(cfg.CA.UserCAPublicKeyFile)
	if err != nil {
		return err
	}
	signer, err := ca.NewStepCA(ca.StepConfig{
		URL: cfg.CA.URL, RootCAFile: cfg.CA.RootCAFile, ProvisionerName: cfg.CA.ProvisionerName,
		JWKFile: cfg.CA.JWKFile, JWKPasswordFile: cfg.CA.JWKPasswordFile, Audience: cfg.CA.Audience,
		SignPath: cfg.CA.SignPath, ValidBefore: cfg.CA.ValidBefore, Timeout: cfg.CA.Timeout.D(),
		UserCAPublicKeys: caKeys, MaxLifetime: cfg.CA.MaxCertLifetime.D(), AllowedExts: cfg.CA.AllowedExtensions,
	})
	if err != nil {
		return err
	}

	hub := agenthub.New(agenthub.Config{
		ServerID: cfg.ServerID, Mux: cfg.Smux.Mux(), TicketTTL: cfg.TicketTTL.D(),
		HeartbeatTimeout: cfg.HeartbeatTimeout.D(), StreamOpen: cfg.StreamOpen.D(), MaxStreams: cfg.MaxStreams,
	}, store, aud, log)
	revoke := true
	if cfg.Sessions.RevokeActive != nil {
		revoke = *cfg.Sessions.RevokeActive
	}
	mgr := sessions.NewManager(sessions.Config{
		AttachTimeout: cfg.Sessions.AttachTimeout.D(), SSHHandshake: cfg.Sessions.SSHHandshake.D(),
		MaxSessionDuration: cfg.Sessions.MaxSessionDuration.D(), MaxPerUser: cfg.Sessions.MaxPerUser,
		MaxTotal: cfg.Sessions.MaxTotal, RevokeActive: revoke,
	}, store, hub, signer, aud, log)

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
	auth, err := authn.New(ctx, authn.Config{OIDC: oidcCfg, DevLogin: cfg.DevLogin, SessionTTL: cfg.WebSession.D(), SecureCookie: secure}, aud, log)
	if err != nil {
		return err
	}

	srv := &server.Server{Store: store, Hub: hub, Sessions: mgr, Auth: auth, Audit: aud, Log: log, AllowedOrigins: []string{pub.Scheme + "://" + pub.Host}}

	// SIGHUP reloads the policy file; grants change without touching hosts.
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
			log.Info("policy reloaded", "revision", s.Revision)
		}
	}()

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
	hub.Shutdown()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = webSrv.Shutdown(sctx)
	_ = agentSrv.Shutdown(sctx)
	return nil
}
