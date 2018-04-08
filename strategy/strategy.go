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

var (
	// ErrCredentialsNotFound is returned if authenticate credentials are missing,
	// mostly used for LocalStrategy.
	ErrCredentialsNotFound = errors.New("Credentials are missing")

	// ErrJWTNotFound is returned if JWT not found, used by JWTStrategy
	ErrJWTNotFound = errors.New("JWT not found")
)
