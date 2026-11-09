package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/spf13/cobra"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/indexyz/osmium/internal/agent"
	"github.com/indexyz/osmium/internal/config"
)

func newAgentCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "agent",
		Short: "运行主机 Agent（只转发到本机配置的 sshd）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runAgent(cfgPath, newLogger())
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		},
	}
	c.Flags().StringVarP(&cfgPath, "config", "c", "agent.json", "Agent 配置文件")
	return c
}

func runAgent(path string, log *slog.Logger) error {
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
	return agent.Run(ctx, agent.Options{
		ServerURL: cfg.ServerURL, TLS: tlsCfg, SSHTarget: cfg.SSHTarget, Labels: cfg.Labels, Version: version,
		MaxStreams: cfg.MaxStreams, Heartbeat: cfg.Heartbeat.D(), StreamOpen: cfg.StreamOpen.D(), TCPDial: cfg.TCPDial.D(),
		RelayDrain: cfg.RelayDrain.D(), ReconnectMax: cfg.ReconnectMax.D(), Mux: cfg.Smux.Mux(), Log: log,
	})
}
