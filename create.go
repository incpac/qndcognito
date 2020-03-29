package main

import (
	"fmt"
	"log"
	"github.com/aws/aws-sdk-go/aws"
	awsSession "github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

func Create(email string, password string, name string, config CognitoConfig) {

	conf := &aws.Config{Region: aws.String(config.AwsRegion)}
	session, err := awsSession.NewSession(conf)
	if err != nil {
		panic(err)
	}

	cognitoClient := cognito.New(session)

	user := &cognito.SignUpInput{
		Username: aws.String(email),
		Password: aws.String(password),
		ClientId: aws.String(config.ClientId),
		UserAttributes: []*cognito.AttributeType{
			{
				Name:	aws.String("name"),
				Value:	aws.String(name),
			},
		},
	}

	_, err = cognitoClient.SignUp(user)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sucess")
}