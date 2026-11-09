package main

import (
	"github.com/spf13/cobra"

	"github.com/indexyz/osmium/internal/agent"
)

func newAgentCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "agent",
		Short: "运行主机 Agent（只转发到本机配置的 sshd；边缘设备请用更小的 osmium-agent）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return agent.RunConfig(cfgPath, version, newLogger())
		},
	}
	c.Flags().StringVarP(&cfgPath, "config", "c", "agent.json", "Agent 配置文件")
	return c
}
