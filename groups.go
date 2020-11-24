package oauthsdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var authUrl string
var client_id string
var client_secret string

var graphBaseUrl string = "https://graph.microsoft.com"

type GraphResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
}

func NewGraph(id string, secret string, url string) error {
	if id == "" || secret == "" || url == "" {
		return errors.New("Parameters cannot be nil")
	}

	if len(Certs) == 0 {
		return errors.New("Certs have not been populated, Please run the New method first")
	}
	authUrl = url
	client_id = id
	client_secret = secret

	err := getGraphToken(client_id, client_secret)

	if err != nil {
		return errors.New(fmt.Sprint(". Error => ", err))
	}

	return nil
}

func getGraphToken(client_id string, client_secret string) error {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("resource", "https://graph.microsoft.com")
	data.Set("client_id", client_id)
	data.Set("client_secret", client_secret)
	data.Set("scope", "Calendar.ReadWrite.All")

	client := &http.Client{}
	r, _ := http.NewRequest("POST", authUrl, strings.NewReader(data.Encode()))

	resp, err := client.Do(r)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.New("Unable to read token response body")
	}

	var response GraphResponse
	json.Unmarshal(body, &response)

	t, err := Parse(response.AccessToken, false)
	if err != nil {
		return err
	}

	GraphAccessToken = *t

	return nil

}

func (t *Token) validateTokenCurrent() bool {
	var exp string
	for _, val := range t.Claims {
		if val.Claim == "exp" {
			exp = val.Value
		}
	}

	f, err := strconv.ParseFloat(exp, 64)

	expiry := time.Unix(int64(f), 0)

	if err != nil {
		fmt.Println(err)
		return false
	}

	if expiry.After(time.Now()) {
		return true
	}

	return false
}

func (t *Token) userInGroup(upn string, groupObjectId string) (bool, error) {

	if !GraphAccessToken.validateTokenCurrent() {
		getGraphToken(client_id, client_secret)
	}

	client := &http.Client{}
	r, _ := http.NewRequest("GET", graphBaseUrl+"users/"+upn+"/memberOf", nil)
	r.Header.Set("Authorization", GraphAccessToken.Token.Raw)
	r.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(r)
	if err != nil {
		fmt.Print(err)
		return false, errors.New(fmt.Sprint("Error making HTTP call. Error => ", err))
	}
	if resp.StatusCode != 200 {
		fmt.Print("Unable to validate JWT User is a valid member of the security group")
		return false, errors.New("Unable to validate JWT User is a valid member of the security group")
	}

	var groups UsersGroupMembership

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &groups)

	for _, group := range groups.Value {
		if group.ID == groupObjectId {
			return true, nil
		}
	}

	return false, nil
}

type UsersGroupMembership struct {
	OdataContext string `json:"@odata.context"`
	Value        []struct {
		OdataType                     string        `json:"@odata.type"`
		ID                            string        `json:"id"`
		DeletedDateTime               interface{}   `json:"deletedDateTime"`
		Description                   string        `json:"description"`
		DisplayName                   string        `json:"displayName"`
		RoleTemplateID                string        `json:"roleTemplateId,omitempty"`
		Classification                interface{}   `json:"classification,omitempty"`
		CreatedDateTime               time.Time     `json:"createdDateTime,omitempty"`
		CreationOptions               []interface{} `json:"creationOptions,omitempty"`
		ExpirationDateTime            interface{}   `json:"expirationDateTime,omitempty"`
		GroupTypes                    []interface{} `json:"groupTypes,omitempty"`
		IsAssignableToRole            interface{}   `json:"isAssignableToRole,omitempty"`
		Mail                          string        `json:"mail,omitempty"`
		MailEnabled                   bool          `json:"mailEnabled,omitempty"`
		MailNickname                  string        `json:"mailNickname,omitempty"`
		MembershipRule                interface{}   `json:"membershipRule,omitempty"`
		MembershipRuleProcessingState interface{}   `json:"membershipRuleProcessingState,omitempty"`
		OnPremisesDomainName          string        `json:"onPremisesDomainName,omitempty"`
		OnPremisesLastSyncDateTime    time.Time     `json:"onPremisesLastSyncDateTime,omitempty"`
		OnPremisesNetBiosName         string        `json:"onPremisesNetBiosName,omitempty"`
		OnPremisesSamAccountName      string        `json:"onPremisesSamAccountName,omitempty"`
		OnPremisesSecurityIdentifier  string        `json:"onPremisesSecurityIdentifier,omitempty"`
		OnPremisesSyncEnabled         bool          `json:"onPremisesSyncEnabled,omitempty"`
		PreferredDataLocation         interface{}   `json:"preferredDataLocation,omitempty"`
		PreferredLanguage             interface{}   `json:"preferredLanguage,omitempty"`
		ProxyAddresses                []string      `json:"proxyAddresses,omitempty"`
		RenewedDateTime               time.Time     `json:"renewedDateTime,omitempty"`
		ResourceBehaviorOptions       []interface{} `json:"resourceBehaviorOptions,omitempty"`
		ResourceProvisioningOptions   []interface{} `json:"resourceProvisioningOptions,omitempty"`
		SecurityEnabled               bool          `json:"securityEnabled,omitempty"`
		SecurityIdentifier            string        `json:"securityIdentifier,omitempty"`
		Theme                         interface{}   `json:"theme,omitempty"`
		Visibility                    interface{}   `json:"visibility,omitempty"`
		OnPremisesProvisioningErrors  []interface{} `json:"onPremisesProvisioningErrors,omitempty"`
	} `json:"value"`
}
