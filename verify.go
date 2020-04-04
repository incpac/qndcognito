// Based on https://github.com/mura123yasu/go-cognito 

package main 

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
	jwt "github.com/dgrijalva/jwt-go"
)

// JWK is a JSON data struct for a Cognito JWK key
type JWK struct {
	Alg	string 
	E 	string 
	Kid 	string 
	Nty	string 
	N 	string
	Use 	string
}

// jwkBundle is a data struct for a JSON Web Key
type jwkBundle struct {
	Keys []JWK
}

func getJwks(url string) (map[string]JWK, error) {
	client := &http.Client{ Timeout: 10*time.Second }
	
	response, err := client.Get(url)
	if err != nil { return nil, err	}

	defer response.Body.Close()

	bundle := &jwkBundle{}
	json.NewDecoder(response.Body).Decode(bundle)

	jwkMap := make(map[string]JWK, 0)

	for _, jwk := range bundle.Keys {
		jwkMap[jwk.Kid] = jwk 
	}

	return jwkMap, nil
}


func convertPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil { return nil, err }

	if len(e) < 4 {
		temp := make([]byte, 4)
		copy(temp[4-len(e):], e)
		e = temp
	}

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil { return nil, err }

	publicKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(e[:])),
	}

	publicKey.N.SetBytes(n)

	return publicKey, nil
}



func validateExpired(claims jwt.MapClaims) (bool, error) {
	rawExp, ok := claims["exp"]
	if !ok {
		return false, errors.New("no expiration in token")
	}

	exp, ok := rawExp.(float64)
	if !ok {
		return false, errors.New("cannot parse token expiration")
	}

	now := time.Now().Unix()
	if int64(exp) > now {
		return true, nil
	}

	return false, nil
}

func validateClaimItem(key string, keyShouldBe []string, claims jwt.MapClaims) (bool, error) {
	val, ok := claims[key]
	if !ok {
		return false, errors.New("key does not exist in token")
	}

	valStr, ok := val.(string)
	if !ok {
		return false, errors.New("cannot convert value to string")
	}

	for _, shouldBe := range keyShouldBe {
		if valStr == shouldBe {
			return true, nil
		}
	}
	return false, nil
}

func validateTokenUsage(claims jwt.MapClaims) (bool, error) {
	tokenUse, ok := claims["token_use"]
	if !ok {
		return false, errors.New("missing token_use from token")
	}

	tokenUseStr, ok := tokenUse.(string)
	if !ok {
		return false, errors.New("unable to convert token_use")
	}

	if tokenUseStr == "id" || tokenUseStr == "access" {
		return true, nil
	}

	return false, nil
}

func validateAwsJwtClaims(claims jwt.MapClaims, region, userPoolID string) (bool, error) {
	issShouldBe := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v", region, userPoolID)
	issIsValid, err := validateClaimItem("iss", []string{ issShouldBe }, claims)
	if err != nil {	return false, err }
	if !issIsValid { return false, errors.New("iss is not valid") }

	valid, err := validateTokenUsage(claims)
	if err != nil {	return false, err }
	if !valid { return false, errors.New("token is not valid for authentication") }

	valid, err = validateExpired(claims)
	if err != nil { return false, err }
	if !valid { return false, errors.New("token is expired") }

	return true, nil
}

func validateToken(tokenStr, region, userPoolID string, jwk map[string]JWK) (bool, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"]
		if !ok { return nil, errors.New("token missing kid") }
		
		kidStr, ok := kid.(string)
		if !ok { return nil, errors.New("cannot parse kid from token") }

		key := jwk[kidStr]
		rsaPublicKey, err := convertPublicKey(key)
		if err != nil { return nil, err }

		return rsaPublicKey, nil
	})

	if err != nil { return false, err }

	claims := token.Claims.(jwt.MapClaims)

	iss, ok := claims["iss"]
	if !ok { return false, errors.New("token does not contain issuer")}
	issStr := iss.(string)
	if strings.Contains(issStr, "cognito-idp") {
		valid, err := validateAwsJwtClaims(claims, region, userPoolID)
		if err != nil { return false, err }
		if !valid { return false, errors.New("jwt not valid cognito token") }
	}

	if token.Valid {
		return true, nil
	}

	return false, nil
}


func Verify(token string, config CognitoConfig) {

	jwkUrl := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v/.well-known/jwks.json", config.AwsRegion, config.UserPoolID)
	jwk, err := getJwks(jwkUrl)
	if err != nil {
		log.Fatal(err)
	}

	valid, err := validateToken(token, config.AwsRegion, config.UserPoolID, jwk)
	if err != nil {
		log.Fatal(err)
	}

	if valid {
		log.Printf("Token is valid")
	} else {
		log.Printf("Token is NOT valid")
	}

}


