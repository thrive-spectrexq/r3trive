package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/output"
	"github.com/thrive-spectrexq/r3trive/internal/plugins"
	"github.com/thrive-spectrexq/r3trive/internal/plugins/builtin"
)

var (
	pluginsVerbose bool
)

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage and inspect R3TRIVE integration plugins",
		Long: `Inspect and verify installed plugins, including built-in SIEM exporters,
ticketing connectors, and threat intelligence integrations.`,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all available plugins",
		RunE:  runPluginsList,
	}

	listCmd.Flags().BoolVarP(&pluginsVerbose, "verbose", "v", false, "display detailed plugin information")

	cmd.AddCommand(listCmd)
	return cmd
}

func runPluginsList(cmd *cobra.Command, args []string) error {
	allPlugins := []plugins.Plugin{
		builtin.NewSplunkPlugin(),
		builtin.NewElasticsearchPlugin(),
		builtin.NewJiraPlugin(),
		builtin.NewPagerDutyPlugin(),
		builtin.NewVirusTotalPlugin(),
		builtin.NewMISPPlugin(),
	}

	outFmt, _ := output.ParseFormat(outputFmt)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	headers := []string{"ID", "NAME", "TYPE", "VERSION", "STATUS"}
	if pluginsVerbose {
		headers = append(headers, "API_VER", "DESCRIPTION")
	}

	var rows [][]string
	for _, p := range allPlugins {
		meta := p.Metadata()
		row := []string{
			meta.ID,
			meta.Name,
			string(meta.Type),
			meta.Version,
			"loaded",
		}
		if pluginsVerbose {
			row = append(row, meta.APIVersion, meta.Description)
		}
		rows = append(rows, row)
	}

	if outFmt == output.FormatTable {
		fmt.Println("═══════════════════════════════════════════")
		fmt.Println(" R3TRIVE Installed Plugins")
		fmt.Println("═══════════════════════════════════════════")
		fmt.Println()
	}

	return formatter.WriteTable(headers, rows)
}
