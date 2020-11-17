package oauthsdk

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

type MicrosoftoAuth2Keys struct {
	Keys []struct {
		Kty string   `json:"kty"`
		Use string   `json:"use"`
		Kid string   `json:"kid"`
		X5T string   `json:"x5t"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5C []string `json:"x5c"`
	} `json:"keys"`
}

type MicrosoftOAuthSigningCerts struct {
	Kid         string
	Certificate string
}

func getMicrosoftKeys(source string) (MicrosoftoAuth2Keys, error) {
	//https://login.microsoftonline.com/common/discovery/keys
	var keys MicrosoftoAuth2Keys
	client := &http.Client{}
	// r, _ := http.NewRequest("GET", "https://login.microsoftonline.com/common/discovery/keys", nil)
	r, err := http.NewRequest("GET", source, nil)

	if err != nil {
		return MicrosoftoAuth2Keys{}, errors.New("Unable to create HTTP Request.")
	}

	resp, err := client.Do(r)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		log.Print("Unable to get Microsoft oAuth2 Signing keys")
		body, _ := ioutil.ReadAll(resp.Body)
		log.Println(resp.Status)
		log.Printf("%+v\n", string(body))
		return MicrosoftoAuth2Keys{}, errors.New("Unable to get Microsoft oAuth2 Signing keys. Response Code was not 200")
	}

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &keys)
	if err != nil {
		log.Print("Unable to unmarshal response from Microsoft API to MicrosoftoAuth2Keys object")
		return MicrosoftoAuth2Keys{}, errors.New("Unable to unmarshal response from Microsoft API to MicrosoftoAuth2Keys object")
	}

	return keys, nil
}

func GetSigningCerts(oAuth2SigningKeys MicrosoftoAuth2Keys) []MicrosoftOAuthSigningCerts {
	certs := make([]MicrosoftOAuthSigningCerts, len(oAuth2SigningKeys.Keys))
	for i, key := range oAuth2SigningKeys.Keys {
		pre := "-----BEGIN CERTIFICATE-----\n"
		suffix := "\n-----END CERTIFICATE-----"
		//certs[key.Kid] = pre + key.X5C[0] + suffix
		certs[i].Certificate = pre + key.X5C[0] + suffix
		certs[i].Kid = key.Kid
	}

	return certs
}
