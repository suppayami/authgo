package strategy

import "net/http"

// Strategy authenticates user with credentials gets from an http.Request.
// Authenticate method should return an error if the authentication is unsuccessful;
// otherwise, no error is returned.
type Strategy interface {
	Authenticate(r *http.Request) error
}
