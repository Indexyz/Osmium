package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/indexyz/osmium/internal/config"
)

// RunConfig loads the Agent config file, builds the mTLS client config and
// runs until SIGINT/SIGTERM. Shared by `osmium agent` and the standalone
// osmium-agent binary.
func RunConfig(path, version string, log *slog.Logger) error {
	cfg, err := config.LoadAgent(path)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
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
		ServerURL: cfg.ServerURL, TLS: tlsCfg, SSHTarget: cfg.SSHTarget, Labels: cfg.Labels, Version: version,
		MaxStreams: cfg.MaxStreams, Heartbeat: cfg.Heartbeat.D(), StreamOpen: cfg.StreamOpen.D(), TCPDial: cfg.TCPDial.D(),
		RelayDrain: cfg.RelayDrain.D(), ReconnectMax: cfg.ReconnectMax.D(), Mux: cfg.Smux.Mux(), Log: log,
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
