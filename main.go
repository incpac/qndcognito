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
	var refreshToken string
	var userPoolID string
	var token string

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

	createCommand.Flags().StringVarP(&email,	"email",	"",	"",	"email address of the user")
	createCommand.Flags().StringVarP(&password,	"password",	"",	"",	"password for the user")
	createCommand.Flags().StringVarP(&name,		"name",		"",	"",	"full name of the user")
	createCommand.Flags().StringVarP(&clientId,	"clientid",	"",	"",	"aws cognito client id")
	createCommand.Flags().StringVarP(&awsRegion,	"region",	"",	"",	"aws region the conginot account resides in")
	
	command.AddCommand(createCommand)


	loginCommand := &cobra.Command{
		Use: "login [params]",
		Short: "Create a login session",
		Long: "Create a login session",
		Run: func(cmd *cobra.Command, args []string) {
			config := CognitoConfig{
				ClientId: clientId,
				AwsRegion: awsRegion,
			}

			Login(email, password, config)
		},
	}

	loginCommand.Flags().StringVarP(&email,		"email",	"",	"",	"email address of the user")
	loginCommand.Flags().StringVarP(&password,	"password",	"",	"",	"password for the user")
	loginCommand.Flags().StringVarP(&clientId,	"clientid",	"",	"",	"aws cognito client id")
	loginCommand.Flags().StringVarP(&awsRegion,	"region",	"",	"",	"aws region the conginot account resides in")

	command.AddCommand(loginCommand)


	refreshCommand := &cobra.Command{
		Use: "refresh [params]",
		Short: "Refresh an existing access token",
		Long: "Refresh an existing access token",
		Run: func(cmd *cobra.Command, args []string) {
			config := CognitoConfig{
				ClientId: clientId,
				AwsRegion: awsRegion,
			}

			Refresh(refreshToken, config)
		},
	}

	refreshCommand.Flags().StringVarP(&refreshToken,	"refresh_token",	"",	"",	"Cognito refresh token")
	refreshCommand.Flags().StringVarP(&clientId,		"clientid",	"",	"",	"aws cognito client id")
	refreshCommand.Flags().StringVarP(&awsRegion,		"region",	"",	"",	"aws region the conginot account resides in")

	command.AddCommand(refreshCommand)

	validateCommand := &cobra.Command{
		Use: "validate [params]",
		Short: "",
		Long: "",
		Run: func (cmd *cobra.Command, args []string) {
			config := CognitoConfig{
				AwsRegion: awsRegion,
				UserPoolID: userPoolID,
			}

			Verify(token, config)
		},
	}

	validateCommand.Flags().StringVarP(&token,	"token",	"",	"", 	"JWT token")
	validateCommand.Flags().StringVarP(&userPoolID,	"userpoolid",	"",	"",	"ID for the Cognito UserPool")
	validateCommand.Flags().StringVarP(&awsRegion,	"region",	"",	"",	"AWS region the Cognito account resides in")

	command.AddCommand(validateCommand)

	if err := command.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}

