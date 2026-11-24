package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/indexyz/osmium/internal/client"
)

// exitCodeError makes main exit with ssh's exit code without logging.
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

func newLoginCmd() *cobra.Command {
	var server, caFile string
	var noBrowser bool
	c := &cobra.Command{
		Use:   "login",
		Short: "通过浏览器登录 Server，保存 CLI 令牌",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server == "" {
				if old, err := client.Load(); err == nil {
					server, caFile = old.Server, old.CAFile
				}
			}
			if server == "" {
				return errors.New("--server is required for the first login")
			}
			errOut := cmd.ErrOrStderr()
			creds, err := client.Login(cmd.Context(), client.LoginOptions{Server: server, CAFile: caFile, Open: func(u string) error {
				fmt.Fprintf(errOut, "在浏览器中打开以下地址并确认授权：\n\n  %s\n\n", u)
				if !noBrowser {
					_ = openBrowser(u)
				}
				return nil
			}})
			if err != nil {
				return err
			}
			name := creds.User.DisplayName
			if name == "" {
				name = creds.User.ID
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已登录 %s（%s），有效期至 %s\n", creds.Server, name, creds.ExpiresAt.Local().Format("2006-01-02 15:04"))
			return nil
		},
	}
	c.Flags().StringVarP(&server, "server", "s", "", "Server 地址，例如 https://ssh.example.com（默认沿用上次登录）")
	c.Flags().StringVar(&caFile, "ca-file", "", "信任的 Server CA 证书（PEM），默认使用系统根证书")
	c.Flags().BoolVar(&noBrowser, "no-browser", false, "只打印授权地址，不自动打开浏览器")
	return c
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "吊销并删除本地保存的 CLI 令牌",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if api, err := client.NewAPI(); err == nil {
				if err := api.Logout(cmd.Context()); err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "warning: server-side revoke failed:", err)
				}
			}
			return client.Remove()
		},
	}
}

func newHostsCmd() *cobra.Command {
	var labels []string
	var query, status string
	var limit int
	var all bool
	c := &cobra.Command{
		Use:   "hosts",
		Short: "列出有权访问的主机",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			var hosts []client.Host
			var total int
			var hasMore bool
			if all {
				cursor := ""
				for {
					page, err := api.HostsPage(cmd.Context(), client.HostPageQuery{
						Labels: labels, Query: query, Status: status, Cursor: cursor, Limit: 500,
					})
					if err != nil {
						return err
					}
					total = page.Total
					hosts = append(hosts, page.Items...)
					if page.NextCursor == "" || len(page.Items) == 0 {
						break
					}
					cursor = page.NextCursor
				}
			} else {
				page, err := api.HostsPage(cmd.Context(), client.HostPageQuery{
					Labels: labels, Query: query, Status: status, Limit: limit,
				})
				if err != nil {
					return err
				}
				hosts = page.Items
				total = page.Total
				hasMore = page.NextCursor != ""
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tMODE\tSTATUS\tLOGINS\tLABELS")
			for _, h := range hosts {
				var ls []string
				for k, v := range h.PolicyLabels {
					ls = append(ls, k+"="+v)
				}
				sort.Strings(ls)
				mode := h.ConnectionMode
				if mode == "" {
					mode = "tunnel"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.ID, h.DisplayName, mode, h.Status, strings.Join(h.AllowedLoginUsers, ","), strings.Join(ls, ","))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if hasMore {
				fmt.Fprintf(cmd.ErrOrStderr(), "显示前 %d / %d 台主机；使用 -q/-l/--status 缩小范围或 --all 导出全部\n", len(hosts), total)
			}
			return nil
		},
	}
	c.Flags().StringArrayVarP(&labels, "label", "l", nil, "按策略标签筛选，key=value，可重复（AND）")
	c.Flags().StringVarP(&query, "query", "q", "", "按主机 ID 或名称关键字过滤")
	c.Flags().StringVar(&status, "status", "", "按状态筛选（ready|direct|offline|disabled）")
	c.Flags().IntVar(&limit, "limit", 100, "单页返回数量（1–500）")
	c.Flags().BoolVar(&all, "all", false, "自动翻页获取全部匹配主机")
	return c
}

func newSSHCmd() *cobra.Command {
	var noAgent, direct, verbose bool
	var sshBin string
	c := &cobra.Command{
		Use:   "ssh [login@]host-id [ssh 参数或远程命令...]",
		Short: "用本机 OpenSSH 客户端连接主机（自动识别隧道/直连证书模式）",
		Long: `为本次连接生成一次性密钥，由 Server 授权并经 step-ca 签发短期证书，
把密钥和证书以限时方式加入 ssh-agent（SSH_AUTH_SOCK），再运行本机 ssh。
对隧道主机经由 Agent 隧道连接，对直连（无 Agent）主机直接连接目标 sshd。
主机公钥按策略中登记的值或信任的 Host CA 严格校验。host-id 之后的参数原样传给 ssh。`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login, host := "", args[0]
			if l, h, ok := strings.Cut(host, "@"); ok {
				login, host = l, h
			}
			api, err := client.NewAPI()
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM)
			defer stop()
			// Ctrl-C belongs to the remote shell; ssh handles it itself.
			signal.Ignore(os.Interrupt)
			code, err := api.SSH(ctx, client.SSHOptions{HostID: host, Login: login, Args: args[1:], SSHBinary: sshBin, NoAgent: noAgent, Direct: direct, Verbose: verbose,
				Stdin: cmd.InOrStdin(), Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr()})
			if err != nil {
				return err
			}
			if code != 0 {
				return exitCodeError(code)
			}
			return nil
		},
	}
	c.Flags().SetInterspersed(false) // everything after host-id goes to ssh
	c.Flags().BoolVar(&noAgent, "no-agent", false, "不使用 ssh-agent，把临时私钥写入私有临时目录")
	c.Flags().BoolVar(&direct, "direct", false, "强制使用直连（无 Agent）短期证书模式")
	c.Flags().StringVar(&sshBin, "ssh", "ssh", "OpenSSH 客户端可执行文件")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "输出会话进度")
	return c
}

func newProxyConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "proxy-connect SOCKET",
		Short:  "ssh ProxyCommand 辅助命令（内部使用）",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.ProxyConnect(args[0], os.Stdin, os.Stdout)
		},
	}
}
