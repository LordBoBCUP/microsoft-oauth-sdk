package oauthsdk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	EncodedToken string
	Audience     string
	Token        *jwt.Token
	Claims       []struct {
		Claim string
		Value string
	}
}

var Certs []MicrosoftOAuthSigningCerts

func New(signingSource string) error {
	if signingSource == "" || len(signingSource) < 1 || signingSource[0:4] != "http" {
		return errors.New("Provided signing source not valid. Must be a valid Microsoft AAD or B2C oAuth2 URL")
	}

	keys, err := getMicrosoftKeys(signingSource)
	if err != nil {
		return errors.New("Unable to obtain Microsoft Public Signing Keys")
	}

	Certs = GetSigningCerts(keys)
	return nil
}

func Parse(token string) (*Token, error) {

	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		keyID := token.Header["kid"].(string)

		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %q", token.Header["alg"])
		}

		var cert string

		for _, val := range Certs {
			if val.Kid == keyID {
				cert = val.Certificate
			}
		}

		if cert == "" {
			return nil, errors.New("Key in tokeen header doesn't match signing keys. Invalid Token.")
		}

		cert1 := convertKey(cert)
		return cert1, nil

	})

	if err != nil {
		return nil, err
	}

	var res Token

	res.Token = t

	return &res, nil

}

func (t *Token) Validate(audience string) (bool, error) {
	t.Audience = audience

	claims, err := extractClaims(t.Token)
	if err != nil {
		return false, err
	}

	if claims["aud"].(string) != audience {
		// return "", "", fmt.Errorf("mismatched audience. aud field %q does not match %q", claims["aud"], aud)
		fmt.Printf("mismatched audience. aud field %q does not match %q", claims["aud"], audience)
		return false, errors.New(fmt.Sprintf("mismatched audience. aud field %q does not match %q", claims["aud"], audience))
	}

	for key, val := range claims {
		x := struct {
			Claim string
			Value string
		}{
			key,
			fmt.Sprintf("%v", val),
		}
		t.Claims = append(t.Claims, x)
	}

	return true, nil
}

func (t *Token) ValidateCustomClaims(claims map[string]string) (bool, error, []string, []string) {
	// For each claim, validate it exists in the token

	var valid []string

	var invalid []string

	for key, element := range claims {
        if checkInternalClaim(t.Claims, key, element) {
			valid = append(valid, key)
		} else {
			invalid = append(invalid, key)
		}
	}
	
	if (len(invalid) > 0 ){
		return false, errors.New("One or more of the custom claims failed to validate with the token."), valid, invalid
	}

	return true, nil, valid, invalid
}

func checkInternalClaim(claims []struct { Claim string 
	Value string}, key string, value string) bool {

		for _, val := range claims {
			fmt.Println(val.Claim)
			fmt.Println(val.Value)
			
			if val.Claim == key  {
				if val.Value == value {
					return true
				}
			}
		}

		return false
	}

func extractClaims(token *jwt.Token) (jwt.MapClaims, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || token.Valid == false {
		fmt.Println("Unable to extrat claims. Token is either not valid or an error has occurred.")
		return nil, errors.New("Unable to extrat claims. Token is either not valid or an error has occurred.")
	}

	// return claims["email"].(string), claims["sub"].(string), nil
	return claims, nil
}

func convertKey(key string) interface{} {
	certPEM := key
	certPEM = strings.Replace(certPEM, "\\n", "\n", -1)
	certPEM = strings.Replace(certPEM, "\"", "", -1)
	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	return rsaPublicKey
}
