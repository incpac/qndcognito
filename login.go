package main

import (
	"log"
	"github.com/aws/aws-sdk-go/aws"
	awsSession "github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

func Login(email string, password string, config CognitoConfig) {

	conf := &aws.Config{Region: aws.String(config.AwsRegion)}
	session, err := awsSession.NewSession(conf)
	if err != nil {
		panic(err)
	}

	cognitoClient := cognito.New(session)

	res, err := cognitoClient.InitiateAuth(&cognito.InitiateAuthInput{
		AuthFlow:	aws.String("USER_PASSWORD_AUTH"),
		AuthParameters:	map[string]*string{
			"USERNAME":	aws.String(email),
			"PASSWORD":	aws.String(password),
		},
		ClientId:	aws.String(config.ClientId),
	})

	if err != nil {
		log.Fatal(err)
	}

	log.Printf(res.AuthenticationResult.String())
}