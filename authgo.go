// Package authgo provides authentication middlewares for Golang handlers.
package authgo

import (
	"net/http"

	"github.com/suppayami/authgo/strategy"
)

func authRoute(handler, failHandler http.Handler, strategy strategy.Strategy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := strategy.Authenticate(r); err != nil {
			failHandler.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func composeStrategy(strategies []strategy.Strategy) strategy.Strategy {
	return strategy.Func(func(r *http.Request) error {
		for _, s := range strategies {
			if err := s.Authenticate(r); err != nil {
				continue
			}
			return nil
		}
		return strategy.ErrAuthenticationFailed
	})
}

// MakeMiddleware makes a simple middleware which only takes main handler as parameters.
// Always use this to make middleware for simplification and compatible with other mux libraries.
func MakeMiddleware(
	failHandler http.Handler,
	strategy strategy.Strategy,
) func(handler http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return authRoute(handler, failHandler, strategy)
	}
}

// MakeComposedMiddleware makes a middleware which only takes main handler as parameters.
// This function will compose all strategies and successfully authenticate if one of the
// given strategy succeed.
func MakeComposedMiddleware(
	failHandler http.Handler,
	strategies []strategy.Strategy,
) func(handler http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return authRoute(handler, failHandler, composeStrategy(strategies))
	}
}
