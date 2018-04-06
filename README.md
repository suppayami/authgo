# Authgo

> Authentication middleware for Go. Inspired from passport.js

## Usage
Example:

```golang
package main

import (
    "errors"
    "log"
    "net/http"

    "github.com/suppayami/authgo"
    "github.com/suppayami/authgo/strategy"
)

func main() {
    // handler need to be authenticated before access
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Authenticate Success!"))
    })

    // fail handler, use when authentication failed
    failHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(401)
        w.Write([]byte("401 Unauthorized"))
    })

    // create an authentication strategy
    localStrategy, _ := strategy.NewLocalStrategy(
        nil,
        func(credentials strategy.LocalCredentials) error {
            // should verify credentials from database instead
            if credentials.Username == "test" && credentials.Password == "test" {
                return nil
            }
            return errors.New("wrong username or password")
        },
    )

    // create a middleware
    middleware := authgo.MakeMiddleware(failHandler, localStrategy)

    // create a route and apply the middleware to handler
    http.Handle("/protected", middleware(handler))
    log.Fatal(http.ListenAndServe(":3000", nil))
}
```