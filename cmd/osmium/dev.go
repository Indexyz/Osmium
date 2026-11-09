package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"

	"github.com/indexyz/osmium/internal/devpki"
)

func newDevCmd() *cobra.Command {
	dev := &cobra.Command{Use: "dev", Short: "本地开发工具（禁止用于生产）"}
	var out, hosts, agents string
	pki := &cobra.Command{
		Use:   "pki",
		Short: "生成开发用的 Agent mTLS 证书",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDevPKI(out, split(hosts), split(agents))
		},
	}
	pki.Flags().StringVarP(&out, "out", "o", "dev/pki", "输出目录")
	pki.Flags().StringVar(&hosts, "server-hosts", "localhost,127.0.0.1", "Agent 监听证书的 DNS 名或 IP，逗号分隔")
	pki.Flags().StringVar(&agents, "agents", "agent-123", "Agent 客户端证书 CN，逗号分隔，须与策略中的 agent.client_cert_cn 一致")
	dev.AddCommand(pki)
	return dev
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runDevPKI(out string, hosts, agents []string) error {
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	ca, err := devpki.NewCA("osmium-dev-agent-ca")
	if err != nil {
		return err
	}
	if err := devpki.WriteFiles(out, "agent-ca", ca.Cert, ca.Key); err != nil {
		return err
	}
	srv, err := ca.Issue("osmium-agent-listener", hosts, false)
	if err != nil {
		return err
	}
	if err := devpki.WriteFiles(out, "server", srv.Cert, srv.Key); err != nil {
		return err
	}
	for _, cn := range agents {
		l, err := ca.Issue(cn, nil, true)
		if err != nil {
			return err
		}
		if err := devpki.WriteFiles(out, cn, l.Cert, l.Key); err != nil {
			return err
		}
	}
	fmt.Printf("wrote agent-ca, server and %d agent certificate(s) to %s\n", len(agents), out)
	return nil
}
