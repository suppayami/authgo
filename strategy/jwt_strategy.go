package strategy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// JWTStrategy looks for JWT (JSON Web Token) from requests, decodes and
// verifies it for user authentication.
type JWTStrategy struct{}

// JWTLookupFunc looks for JWT from request
type JWTLookupFunc func(r *http.Request) (*string, error)

// JWTVerifyFunc verify
type JWTVerifyFunc func(claims jwt.MapClaims) error

// MakeJWTLookupHeader makes a JWTLookupFunc to look for JWT from header with given
// header name.
func MakeJWTLookupHeader(headerName string) JWTLookupFunc {
	return func(r *http.Request) (*string, error) {
		tokenString := r.Header.Get(headerName)
		if tokenString == "" {
			return nil, fmt.Errorf("jwt not found in header %v", headerName)
		}
		return &tokenString, nil
	}
}

// MakeJWTLookupBearerToken makes a JWTLookupFunc to look for JWT from bearer token
// in header data.
func MakeJWTLookupBearerToken() JWTLookupFunc {
	return func(r *http.Request) (*string, error) {
		tokenString, err := MakeJWTLookupHeader("Authorization")(r)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(*tokenString, "Bearer ") {
			return nil, errors.New("bearer token not found in header")
		}
		return tokenString, nil
	}
}
