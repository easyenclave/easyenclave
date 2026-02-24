package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentHealthEndpoint(t *testing.T) {
	a, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v2/health", nil)
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}
