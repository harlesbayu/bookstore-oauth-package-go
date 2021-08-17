package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/harlesbayu/bookstore-utils-go/rest_errors"
)

const (
	headerXPublic    = "x-public"
	headerXClientId  = "x-client-id"
	headerXCallerId  = "x-caller-id"
	paramAccessToken = "accessToken"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"userId"`
	ClientId int64  `json:"clientId"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))

	if accessToken == "" {
		return nil
	}

	at, err := getAccessToken(accessToken)

	if err != nil {
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(token string) (*accessToken, rest_errors.RestErr) {
	resp, err := http.Get(fmt.Sprintf("http://localhost:3001/oauth/access-token/%s", token))

	if err != nil {
		return nil, rest_errors.NewInternalServerError("error request when trying to get access token", errors.New("request error"))
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, rest_errors.NewInternalServerError("error request when trying to get access token", err)
	}

	var at accessToken
	json.NewDecoder(resp.Body).Decode(&at)

	return &at, nil
}
