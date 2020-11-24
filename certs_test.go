package oauthsdk

import "testing"

func TestGetMicrosoftKeys(t *testing.T) {

	keys, err := getMicrosoftKeys("https://login.microsoftonline.com/common/discovery/keys")

	if err != nil {
		t.Error(err)
	}

	if len(keys.Keys) < 1 {
		t.Error("Keys lenght is less than 1")
	}
}

func TestGetSigningCerts(t *testing.T) {
	keys, _ := getMicrosoftKeys("https://login.microsoftonline.com/common/discovery/keys")

	certs := GetSigningCerts(keys)

	for _, cert := range certs {
		if (len(cert.Certificate) < 100) {
			t.Error("Certificate not valid.")
		}

		if cert.Certificate[27:28] == "-" {
			t.Error("Certificate not valid.")
		}
	}
}