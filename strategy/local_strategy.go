package strategy

import (
	"errors"
	"net/http"
)

// LocalStrategy authenticates user with username and password from form data.
type LocalStrategy struct {
	lookup LocalLookupFunc
	verify LocalVerifyFunc
}

// LocalLookupFunc looks for local credentials
type LocalLookupFunc func(r *http.Request) (*LocalCredentials, error)

// LocalVerifyFunc verifies local credentials
type LocalVerifyFunc func(credentials LocalCredentials) error

// LocalCredentials contains login credentials for LocalStrategy.
type LocalCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Authenticate implementation, first lookup for the credentials then verify them.
func (s *LocalStrategy) Authenticate(r *http.Request) error {
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

// MakeLocalLookupForm creates a LocalLookupFunc which looks for credentials
// from form values.
func MakeLocalLookupForm(usernameField, passwordField string) LocalLookupFunc {
	return func(r *http.Request) (*LocalCredentials, error) {
		err := r.ParseForm()
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()

		credentials := &LocalCredentials{
			r.FormValue(usernameField),
			r.FormValue(passwordField),
		}
		if credentials.Username == "" || credentials.Password == "" {
			return nil, ErrCredentialsNotFound
		}

		return credentials, nil
	}
}

// NewLocalStrategy creates a new LocalStrategy with given lookup and verify
// function, with lookup is optional (which can be nil).
//
// The constructor will assign default lookup function to look for
// credentials from form data and JSON data from request if no custom lookup is
// given. A verify function is required to check if given credentials is valid
// and authenticatable.
//
// Credentials are taken from "username" and "password" field in body by default.
func NewLocalStrategy(
	lookup LocalLookupFunc,
	verify LocalVerifyFunc,
) (*LocalStrategy, error) {
	if lookup == nil {
		lookup = MakeLocalLookupForm("username", "password")
	}
	if verify == nil {
		return nil, errors.New("verify function is required by localStrategy")
	}
	return &LocalStrategy{lookup, verify}, nil
}
