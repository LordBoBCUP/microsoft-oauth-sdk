package oauthsdk

import (
	"fmt"
	"testing"
)


var token string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCIsImtpZCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCJ9.eyJhdWQiOiJhcGk6Ly9iODAxNmRlYS04M2ZkLTQzNjktYjAxZi1lYzk5NDU5YTg3ZTciLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83N2UxY2U3ZS1jZDhjLTQxZjQtYjAyYS0yZTgxOWVkNzgwNjQvIiwiaWF0IjoxNjA1NTgwMzM5LCJuYmYiOjE2MDU1ODAzMzksImV4cCI6MTYwNTU4NDIzOSwiYWNyIjoiMSIsImFpbyI6IkUyUmdZTmoyM0pieFZaUm01c245U2haclhSdkRPUE82ekdPNHY1dktKSjdjV3M2WmNma1pvNWJ5NnBqdUdSUDdiTjI4QXFJa0FRPT0iLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiZjQ1MGQwNTEtMzZiMS00ZmM1LWI5ZjUtYjk2MjJmNjU5MzdjIiwiYXBwaWRhY3IiOiIwIiwiaXBhZGRyIjoiMTIyLjU2LjEwNC4xMTQiLCJuYW1lIjoiQWxleCBEZW1vIEFjY291bnQiLCJvaWQiOiI4MTRiYWExOC1iYTI4LTRkNWQtOWQ3NS0zZDM4ZThlOWU2MmYiLCJyaCI6IjAuQVFZQWZzN2hkNHpOOUVHd0tpNkJudGVBWkZIUVVQU3hOc1ZQdWZXNVlpOWxrM3dHQUk4LiIsInNjcCI6IkFQSS5sb2dpbiIsInN1YiI6IlQ1VDRQLTVBNE9ialEtR084YzFwU2Q0TkE0WVVpbFhZRWlSZGFtRmFXNDAiLCJ0aWQiOiI3N2UxY2U3ZS1jZDhjLTQxZjQtYjAyYS0yZTgxOWVkNzgwNjQiLCJ1bmlxdWVfbmFtZSI6ImRlbW9AYXVnZW4uY28ubnoiLCJ1cG4iOiJkZW1vQGF1Z2VuLmNvLm56IiwidXRpIjoiSXAxYmJYbnk2RU9hd2p2VnZkNFNBQSIsInZlciI6IjEuMCJ9.k18-uaEsqx_QOn0dswcMO1CnpMOzTd9ZzU9pQ5iuT1VdYqraeqT1PpzC3ncPPIoUmWwtqppMm1Oc48RoNrzI0NHHbvXJQY1U1lkVMlSfGvKCBmNNu1MS_0PIeKhR06i5EqkuKubtT9si5h0TGMiNreutIdGbDuAhAe5vm0P3MiOdSloab3EGmrKWUaBHpJ6KNTQ9ooGqPZzh6m8tqh2OU0RXcs6CiQgIF435aqsYnh2g-vTGMmNiwfN-VCERv_DR8MNYHVD0AGd2DyxFDCzq-vUaIdh64rlUQRsItESbQbpa1zi6RlCsY4hUaM81htYxNr_ahlt1LRq4zAkGUA4Fcw"
var audience string = "api://b8016dea-83fd-4369-b01f-ec99459a87e7"

func TestNew(t *testing.T) {
	err := New("https://login.microsoftonline.com/common/discovery/keys")
	if err != nil {
		t.Error("Unable to run New Function. Error => ", err)
	}

	if len(Certs) == 0 {
		t.Error("No certs found.")
	}
}


func TestParse(t *testing.T) {
	x, err := Parse(token)

	if x == nil {
		t.Error("Unable to parse token, nil pointer returned")
	}

	if err != nil {
		t.Error("Unable to parse token. Error => ", err)
	}
}

func TestValidate(t *testing.T) {
	tempToken, err := Parse(token)
	if err != nil {
		t.Error("Failed to parse token. Error => ", err)
	}

	res, err := tempToken.Validate(audience)
	if err != nil {
		t.Error("Error validating token. Error => ", err)
	}

	if !res {
		t.Error("Failed to validate token matches Audience supplied")
	}

}

func TestCustomClaimValidation(t *testing.T) {
	tempToken, err := Parse(token)
	if err != nil {
		t.Error("Unable to parse token")
	}

	var m map[string]string

	m = make(map[string]string)

	m["appid"] = "f450d051-36b1-4fc5-b9f5-b9622f65937c"
	m["lol"] = "123"
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
