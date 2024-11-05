/*
Copyright © 2024 Peeanio

*/
package cmd

import (
	"os"
	"log"
	"net/http"
	"github.com/spf13/cobra"
	"bzt-agent/v2/agent"
)


const endpoint = "http://127.0.0.1:8080"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "v2",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		var conf agent.AgentClientConfig
		conf.Cookies = []http.Cookie{http.Cookie{Name: "token", Value: "baz"}, http.Cookie{Name: "id", Value: "foo"}}
		s_endpoint, err := cmd.Flags().GetString("server")
		if err != nil {
			log.Println(err)
			s_endpoint = endpoint
		}
		agent.Run(conf, s_endpoint)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.v2.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().String("server", "http://127.0.0.1:8080", "Server uri to connect to")
}


