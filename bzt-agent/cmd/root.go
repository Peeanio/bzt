/*
Copyright © 2024 Peeanio

*/
package cmd

import (
	"os"
	"log"
	"net/http"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"bzt-agent/v2/agent"
)

var cfgFile string

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
		conf.Cookies = []http.Cookie{http.Cookie{Name: "token", Value: viper.GetString("token")}, http.Cookie{Name: "id", Value: viper.GetString("agentid")}}
		agent.Run(conf)
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bzt-agent.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	cobra.OnInitialize(initConfig)
	viper.SetDefault("server", "http://127.0.0.1:8080")
	viper.SetDefault("cert", "cert.pem") //cert to use as the agent. Keyfile should be defined in /etc/ipsec.secrets if needed
	viper.SetDefault("token", "token") //agent login token
	viper.SetDefault("serverpeerid", "CN=bzt-server.lan") //cert trust string from cert of bzt-server
	viper.SetDefault("agentid", "agent") //agent identifier
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".bzt-server"
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bzt-agent.yaml")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Println(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
