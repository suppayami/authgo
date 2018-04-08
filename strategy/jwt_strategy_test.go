package strategy_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/dgrijalva/jwt-go"

	"github.com/suppayami/authgo/strategy"
)

var (
	jwtStrategy *strategy.JWTStrategy
)

func init() {
	jwtStrategy, _ = strategy.NewJWTStrategy(
		nil,
		func(claims jwt.MapClaims) error {
			if claims["user"] == "test" {
				return nil
			}
			return errors.New("not valid user")
		},
		func(token *jwt.Token) (interface{}, error) {
			return []byte("testkeyfunc"), nil
		},
	)
}

func TestJWTAuthenticationExpiredToken(t *testing.T) {
	// create GET request with bearer token
	req, err := http.NewRequest("GET", "/login", nil)
	req.Header.Add("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJpYXQiOjE1MjMxOTU1ODQsImV4cCI6OTU0NTk3MTg3LCJhdWQiOiIiLCJzdWIiOiIiLCJ1c2VyIjoidGVzdCJ9.q00bskUmO_8p23t6VG9pAbC4IWL1IsgjC4CLfaFmmec")

	if err != nil {
		t.Fatal(err)
	}

	err = jwtStrategy.Authenticate(req)
	// no err => valid => fail
	if err == nil {
		t.Fatal("Token should not be valid")
	}

	if err.Error() != "Token is expired" {
		t.Fatal("Token should be expired")
	}
}

func TestJWTAuthenticationSuccessful(t *testing.T) {
	// create GET request with bearer token
	req, err := http.NewRequest("GET", "/login", nil)
	req.Header.Add("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJpYXQiOjE1MjMxOTY1NjEsImV4cCI6bnVsbCwiYXVkIjoiIiwic3ViIjoiIiwidXNlciI6InRlc3QifQ.Vk68pSZPv7Bvx7zCImJ4thT15eWo31Qmio-J_7ZxLmo")

	if err != nil {
		t.Fatal(err)
	}

	err = jwtStrategy.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestJWTAuthenticationInvalidUser(t *testing.T) {
	// create GET request with bearer token
	req, err := http.NewRequest("GET", "/login", nil)
	req.Header.Add("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJpYXQiOjE1MjMxOTY1NjEsImV4cCI6bnVsbCwiYXVkIjoiIiwic3ViIjoiIiwidXNlciI6ImZhaWwifQ.ny6Pt7H38lpPV6hQ6lwSMpFDEKu90GJlZSl0ltin10E")

	if err != nil {
		t.Fatal(err)
	}

	err = jwtStrategy.Authenticate(req)
	if err == nil {
		t.Fatal("Token should contains invalid user")
	}
}

func TestJWTAuthenticationNoToken(t *testing.T) {
	// create GET request with bearer token
	req, err := http.NewRequest("GET", "/login", nil)
	req.Header.Add("Authorization", "")

	if err != nil {
		t.Fatal(err)
	}

	err = jwtStrategy.Authenticate(req)
	if err != strategy.ErrJWTNotFound {
		t.Fatal("Token should not be found")
	}
}
