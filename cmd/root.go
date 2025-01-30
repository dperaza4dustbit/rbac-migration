/*
Copyright © 2025 Red Hat, Inc.
*/

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "wscli",
	Short: "CLI tool to migrate Konflux RoleBindings from kubesaw users to sso users",
	Long: `CLI tool to migrate Konflux RoleBindings from kubesaw users and roles to 
predetermined cluster roles and targeting Red Hat sso identities. For example:

wscli migrate -t user/email

Where -t is the identity atribute (username or email) that will be targeted.

This tools assumes you have already authenticated with Red Hat SSO and with the
target kubesaw member cluster`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
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
	// Here you will define your flags and configuration settings at root command.
}
