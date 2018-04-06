package strategy

import (
	"errors"
	"net/http"
)

type localStrategy struct {
	lookup func(r *http.Request) (*LocalCredentials, error)
	verify func(credentials LocalCredentials) error
}

// LocalCredentials contains login credentials for localStrategy.
type LocalCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func localLookup(r *http.Request) (*LocalCredentials, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	credentials := &LocalCredentials{
		r.FormValue("username"),
		r.FormValue("password"),
	}
	if credentials.Username == "" || credentials.Password == "" {
		return nil, errors.New("Credentials are missing")
	}

	return credentials, nil
}

// Authenticate implementation, first lookup for the credentials then verify them.
func (s *localStrategy) Authenticate(r *http.Request) error {
	credentials, err := s.lookup(r)
	if err != nil {
		return err
	}
	err = s.verify(*credentials)
	if err != nil {
		return err
	}
	return nil
}

// NewLocalStrategy creates a new localStrategy with given lookup and verify
// function, with lookup is optional (which can be nil).
//
// localStrategy authenticates user with username and password from form data.
//
// The constructor will assign default lookup function to look for
// credentials from form data and JSON data from request if no custom lookup is
// given. A verify function is required to check if given credentials is valid
// and authenticatable.
//
// Credentials are taken from "username" and "password" field in body.
func NewLocalStrategy(
	lookup func(r *http.Request) (*LocalCredentials, error),
	verify func(credentials LocalCredentials) error,
) (Strategy, error) {
	if lookup == nil {
		lookup = localLookup
	}
	if verify == nil {
		return nil, errors.New("verify function is required by localStrategy")
	}
	return &localStrategy{lookup, verify}, nil
}