package oauthsdk

import (
	"os"
	"testing"
)


func TestNewGraph(t *testing.T) {

	if (os.Getenv("AZURE_CLIENT_ID") == "") || (os.Getenv("AZURE_CLIENT_SECRET") == "") {
		t.Error("Environemnt Variables not set for test. Set these before continuing.")
	}

	if len(Certs) == 0 {
		keys, err := getMicrosoftKeys("https://login.microsoftonline.com/common/discovery/keys")
		if err != nil {
			t.Error(err)
		}
	
		Certs = GetSigningCerts(keys)
	}

	err := NewGraph(os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_CLIENT_SECRET"), "https://login.microsoftonline.com/77e1ce7e-cd8c-41f4-b02a-2e819ed78064/oauth2/token")

	if err != nil {
		t.Error(err)
	}
}

func TestValidateCurrentToken(t *testing.T) {

	if (os.Getenv("AZURE_CLIENT_ID") == "") || (os.Getenv("AZURE_CLIENT_SECRET") == "") {
		t.Error("Environemnt Variables not set for test. Set these before continuing.")
	}

	if len(Certs) == 0 {
		keys, err := getMicrosoftKeys("https://login.microsoftonline.com/common/discovery/keys")
		if err != nil {
			t.Error(err)
		}
	
		Certs = GetSigningCerts(keys)
	}

	err := NewGraph(os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_CLIENT_SECRET"), "https://login.microsoftonline.com/77e1ce7e-cd8c-41f4-b02a-2e819ed78064/oauth2/token")

	if err != nil {
		t.Error(err)
	}

	res, err := GraphAccessToken.Validate("https://graph.microsoft.com", true)
	if err != nil {
		t.Error(err)
	}

	if !res {
		t.Error("Validation Failed.")
	}

	res = GraphAccessToken.validateTokenCurrent()

	if !res {
		t.Error("Token not valid. Expired.")
	}
}

func TestUserInGroup(t *testing.T) {
	
}