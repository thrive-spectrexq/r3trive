package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print R3TRIVE version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.Info())
		},
	}
}
