package strategy

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// JWTStrategy looks for JWT (JSON Web Token) from requests, decodes and
// verifies it for user authentication.
type JWTStrategy struct {
	lookup  JWTLookupFunc
	verify  JWTVerifyFunc
	keyFunc jwt.Keyfunc
}

// JWTLookupFunc looks for JWT from request
type JWTLookupFunc func(r *http.Request) (string, error)

// JWTVerifyFunc verify
type JWTVerifyFunc func(claims jwt.MapClaims) error

// Authenticate implementation, looks for JWT from request, then validates and parses it,
// the parsed data is passed to verify function for authentication.
func (s *JWTStrategy) Authenticate(r *http.Request) error {
	tokenString, err := s.lookup(r)
	if err != nil {
		return err
	}
	token, err := jwt.Parse(tokenString, s.keyFunc)
	if err != nil {
		return err
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	err = s.verify(claims)
	if err != nil {
		return err
	}
	return nil
}

// MakeJWTLookupHeader makes a JWTLookupFunc to look for JWT from header with given
// header name.
func MakeJWTLookupHeader(headerName string) JWTLookupFunc {
	return func(r *http.Request) (string, error) {
		tokenString := r.Header.Get(headerName)
		if tokenString == "" {
			return "", ErrJWTNotFound
		}
		return tokenString, nil
	}
}

// MakeJWTLookupBearerToken makes a JWTLookupFunc to look for JWT from bearer token
// in header data.
func MakeJWTLookupBearerToken() JWTLookupFunc {
	return func(r *http.Request) (string, error) {
		tokenString, err := MakeJWTLookupHeader("Authorization")(r)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(tokenString, "Bearer ") {
			return "", ErrJWTNotFound
		}
		return strings.TrimPrefix(tokenString, "Bearer "), nil
	}
}

// NewJWTStrategy creates a new JWTStrategy with given lookup and verify
// function, along with a jwt.keyfunc to look for JWT private key.
// The lookup function is optional, which is assigned a Authorization Bearer
// lookup in header.
//
// Visit JWT library docs for more information.
func NewJWTStrategy(
	lookup JWTLookupFunc,
	verify JWTVerifyFunc,
	keyFunc jwt.Keyfunc,
) (*JWTStrategy, error) {
	if lookup == nil {
		lookup = MakeJWTLookupBearerToken()
	}
	if verify == nil {
		return nil, errors.New("verify function is required by JWTStrategy")
	}
	if keyFunc == nil {
		return nil, errors.New("key function is required by JWTStrategy")
	}
	return &JWTStrategy{lookup, verify, keyFunc}, nil
}
