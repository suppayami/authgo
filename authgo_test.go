package authgo_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suppayami/authgo"
)

var (
	stubStrategy *fakeStrategy
	middleware   func(handler http.Handler) http.Handler
	req          *http.Request
	handler      http.Handler
)

type fakeStrategy struct {
	success bool
}

func (s *fakeStrategy) Authenticate(r *http.Request) error {
	if s.success {
		return nil
	}
	return errors.New("Authenticate failed")
}

func (s *fakeStrategy) MakeSuccess(flag bool) {
	s.success = flag
}

func init() {
	stubStrategy = &fakeStrategy{false}
	middleware = authgo.MakeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), stubStrategy)
	req, _ = http.NewRequest("POST", "/login", nil)
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthMiddlewareSuccess(t *testing.T) {
	stubStrategy.MakeSuccess(true)

	rr := httptest.NewRecorder()
	handler := middleware(handler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected: %v; got: %v", http.StatusOK, status)
	}
}

func TestAuthMiddlewareFailed(t *testing.T) {
	stubStrategy.MakeSuccess(false)

	rr := httptest.NewRecorder()
	handler := middleware(handler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected: %v; got: %v", http.StatusUnauthorized, status)
	}
}
