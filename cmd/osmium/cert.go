package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/client"
)

func newCertCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cert",
		Short: "签发与管理直连（无 Agent）SSH 用户证书",
	}
	root.AddCommand(newCertLoginCmd(), newCertSignCmd(), newCertEnsureCmd())
	return root
}

func newCertLoginCmd() *cobra.Command {
	var principals []string
	var ttlStr, outDir string
	var noAgent, writeKey bool
	c := &cobra.Command{
		Use:   "login",
		Short: "签发角色/组级直连 SSH 证书（可加载到 ssh-agent 或输出到目录）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var ttl time.Duration
			if ttlStr != "" {
				var err error
				ttl, err = time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
			}
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			res, err := api.IssueCert(cmd.Context(), client.CertOptions{
				Mode:       "role",
				Principals: principals,
				TTL:        ttl,
				OutDir:     outDir,
				LoadAgent:  !noAgent,
				WriteKey:   writeKey,
			})
			if err != nil {
				return err
			}
			printCertResult(cmd, res)
			return nil
		},
	}
	c.Flags().StringArrayVarP(&principals, "principal", "p", nil, "仅申请授权集合中的指定 principal（可重复）")
	c.Flags().StringVar(&ttlStr, "ttl", "", "申请证书有效期（例如 4h，受服务端策略上限约束）")
	c.Flags().StringVar(&outDir, "out", "", "输出密钥与证书的目录（默认不落盘，除非 --no-agent 或 --write-key）")
	c.Flags().BoolVar(&noAgent, "no-agent", false, "不加载到 SSH_AUTH_SOCK，改写入私有目录")
	c.Flags().BoolVar(&writeKey, "write-key", false, "同时将临时私钥与证书写入私有目录")
	return c
}

func newCertSignCmd() *cobra.Command {
	var ttlStr, outDir string
	var noAgent, writeKey bool
	c := &cobra.Command{
		Use:   "sign [login@]host-id",
		Short: "为单台直连主机签发一次性短期 SSH 证书",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login, host := "", args[0]
			if l, h, ok := strings.Cut(host, "@"); ok {
				login, host = l, h
			}
			var ttl time.Duration
			if ttlStr != "" {
				var err error
				ttl, err = time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
			}
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			res, err := api.IssueCert(cmd.Context(), client.CertOptions{
				Mode:      "host",
				HostID:    host,
				Login:     login,
				TTL:       ttl,
				OutDir:    outDir,
				LoadAgent: !noAgent,
				WriteKey:  writeKey,
			})
			if err != nil {
				return err
			}
			printCertResult(cmd, res)
			return nil
		},
	}
	c.Flags().StringVar(&ttlStr, "ttl", "", "申请证书有效期（例如 60s，受服务端上限约束）")
	c.Flags().StringVar(&outDir, "out", "", "输出目录")
	c.Flags().BoolVar(&noAgent, "no-agent", false, "不加载到 SSH_AUTH_SOCK，写入私有目录")
	c.Flags().BoolVar(&writeKey, "write-key", false, "同时写入私有目录")
	return c
}

func newCertEnsureCmd() *cobra.Command {
	var roleMode, quiet bool
	var loginFlag, ttlStr, outDir, minRemStr string
	var principals []string
	c := &cobra.Command{
		Use:   "ensure [login@]host-id",
		Short: "确保目标目录存在未过期证书（供 OpenSSH Match exec 自动调用）",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var ttl, minRem time.Duration
			if ttlStr != "" {
				var err error
				ttl, err = time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
			}
			if minRemStr != "" {
				var err error
				minRem, err = time.ParseDuration(minRemStr)
				if err != nil {
					return fmt.Errorf("invalid --min-remaining: %w", err)
				}
			}
			opt := client.CertOptions{
				Principals:   principals,
				TTL:          ttl,
				OutDir:       outDir,
				LoadAgent:    false,
				WriteKey:     true,
				ReuseValid:   true,
				MinRemaining: minRem,
			}
			if roleMode {
				opt.Mode = "role"
			} else {
				if len(args) != 1 {
					return errors.New("host-id is required (or pass --role)")
				}
				login, host := loginFlag, args[0]
				if l, h, ok := strings.Cut(host, "@"); ok {
					login, host = l, h
				}
				opt.Mode = "host"
				opt.HostID = host
				opt.Login = login
			}
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			res, err := api.IssueCert(cmd.Context(), opt)
			if err != nil {
				return err
			}
			if !quiet {
				printCertResult(cmd, res)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&roleMode, "role", false, "确保角色级证书而非单主机证书")
	c.Flags().StringVar(&loginFlag, "login", "", "目标 Linux 登录账号（可配合 OpenSSH %r）")
	c.Flags().StringArrayVarP(&principals, "principal", "p", nil, "角色模式下限制请求的 principal")
	c.Flags().StringVar(&ttlStr, "ttl", "", "申请证书有效期")
	c.Flags().StringVar(&outDir, "out", "", "证书存放目录")
	c.Flags().StringVar(&minRemStr, "min-remaining", "", "剩余有效期低于该阈值时自动轮换签发")
	c.Flags().BoolVarP(&quiet, "quiet", "q", false, "静默模式（适用于 Match exec）")
	return c
}

func printCertResult(cmd *cobra.Command, res *client.CertResult) {
	out := cmd.OutOrStdout()
	state := "已签发"
	if res.Reused {
		state = "复用有效证书"
	}
	fmt.Fprintf(out, "%s (%s): principals=[%s] valid_until=%s\n",
		state, res.CertID, strings.Join(res.Principals, ", "), res.ValidBefore.Local().Format(time.RFC3339))
	if res.SourceAddress != "" {
		fmt.Fprintf(out, "  source-address: %s\n", res.SourceAddress)
	}
	if res.AgentLoaded {
		fmt.Fprintln(out, "  ssh-agent: 已加载（含自动过期 TTL）")
	}
	if res.KeyPath != "" {
		fmt.Fprintf(out, "  key:  %s\n  cert: %s\n", res.KeyPath, res.CertPath)
	}
	if res.KnownHostsPath != "" {
		fmt.Fprintf(out, "  known_hosts: %s\n", res.KnownHostsPath)
	}
}

func newSSHConfigCmd() *cobra.Command {
	var labels []string
	var prefix, agentSock, matchPattern, knownHosts, writePath string
	var useAgent bool
	c := &cobra.Command{
		Use:   "ssh-config",
		Short: "生成 OpenSSH ~/.ssh/config 配置与 Host CA known_hosts",
		Long: `生成可直接供原生 ssh、scp、rsync、VS Code Remote-SSH 和 Ansible 使用的
OpenSSH 配置片段；若 Server 配置了 SSH Host CA，会同步写入 @cert-authority known_hosts。`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			cfg, err := api.GenerateSSHConfig(cmd.Context(), client.SSHConfigOptions{
				Labels:         labels,
				HostPrefix:     prefix,
				UseAgent:       useAgent,
				AgentSocket:    agentSock,
				MatchPattern:   matchPattern,
				KnownHostsPath: knownHosts,
			})
			if err != nil {
				return err
			}
			if writePath != "" {
				if err := os.MkdirAll(filepath.Dir(writePath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(writePath, []byte(cfg), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "已写入 OpenSSH 配置至 %s\n", writePath)
				return nil
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), cfg)
			return err
		},
	}
	c.Flags().StringArrayVarP(&labels, "label", "l", nil, "按策略标签筛选主机，key=value")
	c.Flags().StringVar(&prefix, "prefix", "", "为生成的 Host 别名添加前缀")
	c.Flags().BoolVar(&useAgent, "use-agent", false, "使用内置 osmium ssh-agent（IdentityAgent）而非按主机 Match exec")
	c.Flags().StringVar(&agentSock, "agent-socket", "", "osmium ssh-agent 套接字路径（配合 --use-agent）")
	c.Flags().StringVar(&matchPattern, "match-pattern", "", "附加通配 Host 规则（如 *.prod.internal，配合 --use-agent 用于未登记主机）")
	c.Flags().StringVar(&knownHosts, "known-hosts", "", "写入 Host CA 的 known_hosts 路径")
	c.Flags().StringVarP(&writePath, "write", "w", "", "直接写入指定文件（如 ~/.ssh/config.d/osmium.conf）而非打印到 stdout")
	return c
}

func newSSHAgentCmd() *cobra.Command {
	var socketPath, ttlStr, renewBeforeStr, checkIntervalStr string
	var principals []string
	c := &cobra.Command{
		Use:   "ssh-agent",
		Short: "运行本地常驻只读 SSH Agent（内存持有证书、自动轮换密钥、吊销秒清）",
		Long: `在本地启动标准 OpenSSH Agent 协议守护进程：
- 临时 Ed25519 私钥与签发证书仅存内存，永不落盘；
- 只读托管：拒绝外部 ssh-add 注入或篡改密钥；
- 临近过期自动生成全新临时密钥并向 Server 续签；
- 定期探测凭证状态，用户被禁用或 Token 被吊销时立即清空内存密钥。`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var ttl, renewBefore, checkInterval time.Duration
			var err error
			if ttlStr != "" {
				if ttl, err = time.ParseDuration(ttlStr); err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
			}
			if renewBeforeStr != "" {
				if renewBefore, err = time.ParseDuration(renewBeforeStr); err != nil {
					return fmt.Errorf("invalid --renew-before: %w", err)
				}
			}
			if checkIntervalStr != "" {
				if checkInterval, err = time.ParseDuration(checkIntervalStr); err != nil {
					return fmt.Errorf("invalid --check-interval: %w", err)
				}
			}
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()
			return api.RunSSHAgent(ctx, client.SSHAgentOptions{
				SocketPath:    socketPath,
				Principals:    principals,
				TTL:           ttl,
				RenewBefore:   renewBefore,
				CheckInterval: checkInterval,
				Log:           newLogger(),
				OnReady: func(sock string, cert *ssh.Certificate) {
					fmt.Fprintf(out, "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", sock)
					fmt.Fprintf(cmd.ErrOrStderr(), "osmium ssh-agent ready: principals=[%s] valid_until=%s\n",
						strings.Join(cert.ValidPrincipals, ", "),
						time.Unix(int64(cert.ValidBefore), 0).Local().Format(time.RFC3339))
				},
			})
		},
	}
	c.Flags().StringVar(&socketPath, "socket", "", "监听的 Unix socket 路径（默认在 osmium 配置目录）")
	c.Flags().StringArrayVarP(&principals, "principal", "p", nil, "仅申请授权集合中的指定 principal（可重复）")
	c.Flags().StringVar(&ttlStr, "ttl", "", "单次证书申请有效期（例如 4h，受服务端策略上限约束）")
	c.Flags().StringVar(&renewBeforeStr, "renew-before", "", "过期前多久触发密钥轮换续签（默认 TTL 的 1/4，最大 15m）")
	c.Flags().StringVar(&checkIntervalStr, "check-interval", "60s", "吊销/禁用状态巡检周期")
	return c
}
