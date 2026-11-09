// Command osmium-agent is the standalone host Agent for small edge devices.
// It links only what the Agent needs (no cobra, Server, CLI or templates);
// `osmium agent` in the main binary is equivalent.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/indexyz/osmium/internal/agent"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	cfg := flag.String("c", "agent.json", "Agent 配置文件")
	flag.StringVar(cfg, "config", "agent.json", "Agent 配置文件")
	showVersion := flag.Bool("version", false, "打印版本并退出")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: osmium-agent [-c agent.json]\n\n运行主机 Agent，只转发到本机配置的 sshd。\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := agent.RunConfig(*cfg, version, slog.New(slog.NewJSONHandler(os.Stderr, nil))); err != nil {
		fmt.Fprintln(os.Stderr, "osmium-agent:", err)
		os.Exit(1)
	}
}
