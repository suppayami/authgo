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

// MakeMiddleware makes a simple middleware which only takes main handler as parameters.
// Always use this to make middleware for simplification and compatible with other mux libraries.
func MakeMiddleware(failHandler http.Handler, strategy strategy.Strategy) func(handler http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return authRoute(handler, failHandler, strategy)
	}
}
