package strategy_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/suppayami/authgo/strategy"
)

var (
	localStrategy strategy.Strategy
)

func init() {
	localStrategy, _ = strategy.NewLocalStrategy(
		nil,
		func(credentials strategy.LocalCredentials) error {
			if credentials.Username == "test" && credentials.Password == "test" {
				return nil
			}
			return errors.New("wrong username or password")
		},
	)
}

func TestLocalAuthenticateSuccess(t *testing.T) {
	payload := url.Values{}
	payload.Set("username", "test")
	payload.Set("password", "test")

	// create POST request with content-type application/x-www-form-urlencoded
	req, err := http.NewRequest("POST", "/login", strings.NewReader(payload.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	err = localStrategy.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalAuthenticateWrongCredentials(t *testing.T) {
	payload := url.Values{}
	payload.Set("username", "test")
	payload.Set("password", "wrongpassword")

	// create POST request with content-type application/x-www-form-urlencoded
	req, err := http.NewRequest("POST", "/login", strings.NewReader(payload.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	err = localStrategy.Authenticate(req)
	if err == nil {
		t.Fatalf("Credentials {username: %v, password: %v} should be wrong",
			payload.Get("username"), payload.Get("password"))
	}
}

func TestLocalAuthenticateMissingCredentials(t *testing.T) {
	payload := url.Values{}
	payload.Set("username", "test")
	payload.Set("password", "")

	// create POST request with content-type application/x-www-form-urlencoded
	req, err := http.NewRequest("POST", "/login", strings.NewReader(payload.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	err = localStrategy.Authenticate(req)
	if err.Error() != "Credentials are missing" {
		t.Fatalf("Credentials {username: %v, password: %v} should be missing",
			payload.Get("username"), payload.Get("password"))
	}
}
