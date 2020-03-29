package main

import (
	"log"
	"os"
	"github.com/spf13/cobra"
)



func main() {
	var email string
	var password string 
	var name string
	var clientId string
	var awsRegion string

	command := &cobra.Command{
		Use: "qndcognito",
		Short: "",
		Long: "",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	createCommand := &cobra.Command{
		Use: "create [params]",
		Short: "Create a new Cognito user",
		Long: "Create a new Cognito user",
		Run: func(cmd *cobra.Command, args []string) {
			config := CognitoConfig{
				ClientId: clientId,
				AwsRegion: awsRegion,
			}

			Create(email, password, name, config)
		},
	}

	createCommand.Flags().StringVarP(&email,		"email",	"",	"",	"email address of the user")
	createCommand.Flags().StringVarP(&password,		"password",	"",	"",	"password for the user")
	createCommand.Flags().StringVarP(&name,			"name",		"", "", "full name of the user")
	createCommand.Flags().StringVarP(&clientId,		"clientid",	"",	"",	"aws cognito client id")
	createCommand.Flags().StringVarP(&awsRegion,	"region",	"",	"",	"aws region the conginot account resides in")
	
	command.AddCommand(createCommand)


	if err := command.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}

