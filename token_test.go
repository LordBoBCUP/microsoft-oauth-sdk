package oauthsdk

import (
	"fmt"
	"testing"
)


var token string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCIsImtpZCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCJ9.eyJhdWQiOiJhcGk6Ly9iODAxNmRlYS04M2ZkLTQzNjktYjAxZi1lYzk5NDU5YTg3ZTciLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83N2UxY2U3ZS1jZDhjLTQxZjQtYjAyYS0yZTgxOWVkNzgwNjQvIiwiaWF0IjoxNjA2MTc3MzAxLCJuYmYiOjE2MDYxNzczMDEsImV4cCI6MTYwNjE4MTIwMSwiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhSQUFBQWpHUlkwVHJFVXE5QWJrUVdXOWNncUN6MzlYOVRtNDZXVnA2ZVNrSXFzcHplV2lscG9scit1NFpxbWdLaDFaNXYiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiZjQ1MGQwNTEtMzZiMS00ZmM1LWI5ZjUtYjk2MjJmNjU5MzdjIiwiYXBwaWRhY3IiOiIwIiwiaXBhZGRyIjoiMTIyLjU2LjEwNC4xMTQiLCJuYW1lIjoiQWxleCBEZW1vIEFjY291bnQiLCJvaWQiOiI4MTRiYWExOC1iYTI4LTRkNWQtOWQ3NS0zZDM4ZThlOWU2MmYiLCJyaCI6IjAuQVFZQWZzN2hkNHpOOUVHd0tpNkJudGVBWkZIUVVQU3hOc1ZQdWZXNVlpOWxrM3dHQUk4LiIsInNjcCI6IkFQSS5sb2dpbiIsInN1YiI6IlQ1VDRQLTVBNE9ialEtR084YzFwU2Q0TkE0WVVpbFhZRWlSZGFtRmFXNDAiLCJ0aWQiOiI3N2UxY2U3ZS1jZDhjLTQxZjQtYjAyYS0yZTgxOWVkNzgwNjQiLCJ1bmlxdWVfbmFtZSI6ImRlbW9AYXVnZW4uY28ubnoiLCJ1cG4iOiJkZW1vQGF1Z2VuLmNvLm56IiwidXRpIjoidm05NFBIcE1ZMFdvaEgxSEVFLWxBQSIsInZlciI6IjEuMCJ9.OwFv02r-UGCtIMhr03R-Udvg-lQo9hHCSpofGXHRsFTLnSO6jWgwt2G0LqCrO2eYVlA6khhUZimw23LCmXlFOODN_JYXpmn419czaDmNJnL5hSUQAcWD1hlXKx7sdnhFANNzGv0tDQdaAnvBmAyWWLl9kpEoUQ6gkuDfOjRJDOQCaHQlIWOYCJoOMHHasGoBl2Wpirk7uktaov_P7QV8O4QO4o49Bpi5gHBZg0NbJzftG9np5SsjxHIKGIkjbcWq15tZKps7Hq1ivR635Ba0NWQXPV-mSEUBEtk_nlIzxD4rKfdMHL8I8Lopge8uONsXAcrOB6DiFrK_LJ_YoYPuCg"
var audience string = "api://b8016dea-83fd-4369-b01f-ec99459a87e7"

func TestNew(t *testing.T) {
	_, err := New("https://login.microsoftonline.com/common/discovery/keys")
	if err != nil {
		t.Error("Unable to run New Function. Error => ", err)
	}

	if len(Certs) == 0 {
		t.Error("No certs found.")
	}
}


func TestParse(t *testing.T) {
	oauth, err := New("https://login.microsoftonline.com/common/discovery/keys")
	x, err := oauth.Parse(token, true)

	if x == nil {
		t.Error("Unable to parse token, nil pointer returned")
	}

	if err != nil {
		t.Error("Unable to parse token. Error => ", err)
	}
}

func TestValidate(t *testing.T) {
	oauth, err := New("https://login.microsoftonline.com/common/discovery/keys")
	tempToken, err := oauth.Parse(token, true)
	if err != nil {
		t.Error("Failed to parse token. Error => ", err)
		return
	}

	res, err := tempToken.Validate(audience, false)
	if err != nil {
		t.Error("Error validating token. Error => ", err)
		return
	}

	if !res {
		t.Error("Failed to validate token matches Audience supplied")
		return
	}

}

func TestCustomClaimValidation(t *testing.T) {
	oauth, err := New("https://login.microsoftonline.com/common/discovery/keys")
	tempToken, err := oauth.Parse(token, true)
	if err != nil {
		t.Error("Unable to parse token")
	}

	var m map[string]string

	m = make(map[string]string)

	m["appid"] = "f450d051-36b1-4fc5-b9f5-b9622f65937c"
	res, err, valid, invalid := tempToken.ValidateCustomClaims(m)

	if err != nil {
		t.Error("Error validing custom claims. Error => ", err)
	}

	if !res {
		t.Error("Custom Claim not validated")
	}

	if (len(invalid) > 0 ){
		fmt.Println("Failed Claims:")
		fmt.Printf("%v", invalid)
	}

	if (len(valid) > 0) { 
		fmt.Println("Successful Claims: ")
		fmt.Printf("%v", valid)
	}

}
