package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easyenclave/easyenclave/v2/internal/gen/controlplaneapi"
)

func TestControlPlaneHealthEndpoint(t *testing.T) {
	a, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/health", nil)
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}

func TestRegisterAgentNonceAndQuoteValidation(t *testing.T) {
	a, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	challengeReq := httptest.NewRequest(http.MethodGet, "/v2/agents/challenge?vm_name=vm-a", nil)
	challengeResp := httptest.NewRecorder()
	a.Handler().ServeHTTP(challengeResp, challengeReq)
	if challengeResp.Code != http.StatusOK {
		t.Fatalf("challenge code=%d", challengeResp.Code)
	}
	var challenge controlplaneapi.ChallengeResponse
	if err := json.NewDecoder(challengeResp.Body).Decode(&challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	body := controlplaneapi.AgentRegisterRequest{
		VmName:         "vm-a",
		NodeSize:       controlplaneapi.AgentRegisterRequestNodeSizeTiny,
		Datacenter:     "baremetal:default",
		ChallengeNonce: challenge.Nonce,
		QuoteB64:       makeQuoteWithNonce(challenge.Nonce),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/v2/agents/register", bytes.NewReader(raw))
	registerResp := httptest.NewRecorder()
	a.Handler().ServeHTTP(registerResp, registerReq)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register code=%d body=%s", registerResp.Code, registerResp.Body.String())
	}
}

func TestRegisterRejectsInvalidNonceBinding(t *testing.T) {
	a, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	challengeReq := httptest.NewRequest(http.MethodGet, "/v2/agents/challenge?vm_name=vm-b", nil)
	challengeResp := httptest.NewRecorder()
	a.Handler().ServeHTTP(challengeResp, challengeReq)
	if challengeResp.Code != http.StatusOK {
		t.Fatalf("challenge code=%d", challengeResp.Code)
	}
	var challenge controlplaneapi.ChallengeResponse
	if err := json.NewDecoder(challengeResp.Body).Decode(&challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	body := controlplaneapi.AgentRegisterRequest{
		VmName:         "vm-b",
		NodeSize:       controlplaneapi.AgentRegisterRequestNodeSizeTiny,
		Datacenter:     "baremetal:default",
		ChallengeNonce: challenge.Nonce,
		QuoteB64:       makeQuoteWithNonce("different-nonce"),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/v2/agents/register", bytes.NewReader(raw))
	registerResp := httptest.NewRecorder()
	a.Handler().ServeHTTP(registerResp, registerReq)
	if registerResp.Code != http.StatusUnauthorized {
		t.Fatalf("register code=%d body=%s", registerResp.Code, registerResp.Body.String())
	}
	if !strings.Contains(registerResp.Body.String(), "REPORTDATA") {
		t.Fatalf("expected reportdata error body, got=%s", registerResp.Body.String())
	}
}

func makeQuoteWithNonce(nonce string) string {
	const (
		headerSize       = 48
		tdReportSize     = 584
		reportDataOffset = headerSize + 520
		reportDataLen    = 64
	)
	quote := make([]byte, headerSize+tdReportSize)
	copy(quote[reportDataOffset:reportDataOffset+reportDataLen], append([]byte(nonce), make([]byte, reportDataLen-len(nonce))...))
	return base64.StdEncoding.EncodeToString(quote)
}
