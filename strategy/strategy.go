// Package strategy contains various authentication strategies for authgo.
package strategy

import (
	"errors"
	"net/http"
)

// Strategy authenticates user with credentials gets from an http.Request.
// Authenticate method should return an error if the authentication is unsuccessful;
// otherwise, no error is returned.
type Strategy interface {
	Authenticate(r *http.Request) error
}

// Func is an adapter to allow the use of ordinary functions as Strategy.
// If f is a function with the appropriate signature, Func(f) is a Strategy
// that calls f.
type Func func(*http.Request) error

// Authenticate calls f(r)
func (f Func) Authenticate(r *http.Request) error {
	return f(r)
}

var (
	// ErrCredentialsNotFound is returned if authenticate credentials are missing,
	// mostly used for LocalStrategy.
	ErrCredentialsNotFound = errors.New("Credentials are missing")

	// ErrJWTNotFound is returned if JWT not found, used by JWTStrategy
	ErrJWTNotFound = errors.New("JWT not found")

	// ErrAuthenticationFailed is returned if Authenticate unsuccessfully
	ErrAuthenticationFailed = errors.New("Authentication failed")
)
