// Command osmium is the single binary for the Web SSH system: the Server,
// the host Agent and local development tools are subcommands.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "osmium",
		Short:         "Web SSH 访问系统：Server、主机 Agent、CLI 客户端与开发工具",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newServerCmd(), newAgentCmd(), newDevCmd(),
		newLoginCmd(), newLogoutCmd(), newHostsCmd(), newSSHCmd(), newProxyConnectCmd(), &cobra.Command{
			Use:   "version",
			Short: "打印版本",
			Args:  cobra.NoArgs,
			Run:   func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), version) },
		})
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var code exitCodeError
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, "osmium:", err)
		os.Exit(1)
	}
}
