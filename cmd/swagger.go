/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"devtool/modules/swagger"

	"github.com/spf13/cobra"
)

var (
	swaggerToGoZeroOutput  string
	swaggerToGoZeroCfgfile string
)

// swaggerCmd represents the swagger command
var swaggerCmd = &cobra.Command{
	Use:   "swagger",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
}

var swaggerToGoZeroCmd = &cobra.Command{
	Use:   "zero",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			return
		}
		swagger.Main(swaggerToGoZeroOutput, swaggerToGoZeroCfgfile, true, args[0])
	},
}

func init() {
	swaggerCmd.AddCommand(swaggerToGoZeroCmd)
	rootCmd.AddCommand(swaggerCmd)

	swaggerCmd.PersistentFlags().StringVarP(&swaggerToGoZeroOutput, "output", "o", "", "输出文件路径")
	swaggerCmd.PersistentFlags().StringVarP(&swaggerToGoZeroCfgfile, "cfgfile", "c", "", "配置文件路径")
}
