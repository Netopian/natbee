package cmd

import (
	api "github.com/Netopian/natbee/api"

	"github.com/spf13/cobra"
)

var (
	filePath string
)

func newSaveCmd() *cobra.Command {
	saveCmd := &cobra.Command{
		Use: "save",
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := client.Save(ctx, &api.SaveReq{FilePath: filePath}); err != nil {
				exitWithError(err)
			}
		},
	}
	saveCmd.PersistentFlags().StringVarP(&filePath, "file", "f", "", "target filepath, will overwrite current file if not specified")
	return saveCmd
}
