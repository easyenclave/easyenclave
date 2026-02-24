package app

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/easyenclave/easyenclave/v2/internal/gen/controlplaneapi"
	"github.com/easyenclave/easyenclave/v2/internal/shared/tdxquote"
	"github.com/easyenclave/easyenclave/v2/internal/shared/version"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeJSON[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	defer r.Body.Close()
	var out T
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		writeJSON(w, http.StatusBadRequest, controlplaneapi.AckResponse{Ok: false, Message: ptr("invalid json")})
		return nil, false
	}
	return &out, true
}

func ptr[T any](v T) *T { return &v }

func sanitizeID(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	in = strings.ReplaceAll(in, " ", "-")
	if in == "" {
		return "unknown"
	}
	return in
}

func writeAck(w http.ResponseWriter, status int, ok bool, message string) {
	var msg *string
	if strings.TrimSpace(message) != "" {
		msg = &message
	}
	writeJSON(w, status, controlplaneapi.AckResponse{Ok: ok, Message: msg})
}

func randomSecret(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (a *App) pruneChallengesLocked(now time.Time) {
	for nonce, rec := range a.challenges {
		if !rec.ExpiresAt.After(now) {
			delete(a.challenges, nonce)
		}
	}
}

func (a *App) issueChallenge(vmName string, ttl time.Duration) (string, time.Time) {
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	nonce := fmt.Sprintf("cp-%s-%d", sanitizeID(vmName), now.UnixNano())

	a.mu.Lock()
	a.pruneChallengesLocked(now)
	a.challenges[nonce] = challengeRecord{
		VMName:    vmName,
		ExpiresAt: expiresAt,
	}
	a.mu.Unlock()

	return nonce, expiresAt
}

func (a *App) consumeChallenge(vmName, nonce string) bool {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	rec, ok := a.challenges[nonce]
	if !ok {
		return false
	}
	delete(a.challenges, nonce)

	if !rec.ExpiresAt.After(now) {
		return false
	}
	return sanitizeID(rec.VMName) == sanitizeID(vmName)
}

func (a *App) GetControlPlaneHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, controlplaneapi.HealthResponse{
		Status:  controlplaneapi.Ok,
		Service: "control-plane-v2",
		Version: ptr(version.Version),
	})
}

func (a *App) GetAgentChallenge(w http.ResponseWriter, _ *http.Request, params controlplaneapi.GetAgentChallengeParams) {
	nonce, expiresAt := a.issueChallenge(params.VmName, 5*time.Minute)
	writeJSON(w, http.StatusOK, controlplaneapi.ChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	})
}

func (a *App) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[controlplaneapi.AgentRegisterRequest](w, r)
	if !ok {
		return
	}

	if strings.TrimSpace(req.VmName) == "" {
		writeAck(w, http.StatusBadRequest, false, "vm_name is required")
		return
	}
	if strings.TrimSpace(req.Datacenter) == "" {
		writeAck(w, http.StatusBadRequest, false, "datacenter is required")
		return
	}
	if !a.consumeChallenge(req.VmName, req.ChallengeNonce) {
		writeAck(w, http.StatusUnauthorized, false, "invalid or expired challenge_nonce")
		return
	}

	parsedQuote, err := tdxquote.ParseQuoteB64(req.QuoteB64)
	if err != nil {
		writeAck(w, http.StatusBadRequest, false, "invalid quote_b64")
		return
	}
	expectedReportDataPrefix := hex.EncodeToString([]byte(req.ChallengeNonce))
	if !strings.HasPrefix(strings.ToLower(parsedQuote.ReportData), expectedReportDataPrefix) {
		writeAck(w, http.StatusUnauthorized, false, "quote REPORTDATA does not match challenge_nonce")
		return
	}

	agentID := fmt.Sprintf("agent-%s-%d", sanitizeID(req.VmName), time.Now().UnixNano())
	secret, err := randomSecret(32)
	if err != nil {
		writeAck(w, http.StatusInternalServerError, false, "failed to mint agent secret")
		return
	}

	a.mu.Lock()
	a.agents[agentID] = &agentRecord{
		AgentID:       agentID,
		VMName:        req.VmName,
		NodeSize:      string(req.NodeSize),
		Datacenter:    req.Datacenter,
		Secret:        secret,
		RegisteredAt:  time.Now().UTC(),
		Status:        string(controlplaneapi.Registering),
		LastTDXReport: parsedQuote.ReportData,
	}
	a.mu.Unlock()

	mode := controlplaneapi.Direct
	writeJSON(w, http.StatusOK, controlplaneapi.AgentRegisterResponse{
		AgentId:        agentID,
		AgentApiSecret: secret,
		Mode:           &mode,
	})
}

func (a *App) AgentHeartbeat(w http.ResponseWriter, r *http.Request, agentID string) {
	req, ok := decodeJSON[controlplaneapi.HeartbeatRequest](w, r)
	if !ok {
		return
	}

	a.mu.Lock()
	rec, exists := a.agents[agentID]
	if exists {
		rec.LastHeartbeat = req.Timestamp
		if req.Health != nil {
			rec.Health = string(*req.Health)
		}
		if req.DeployedApp != nil {
			rec.DeployedApp = *req.DeployedApp
		}
		if req.DeploymentId != nil {
			rec.DeploymentID = *req.DeploymentId
		}
	}
	a.mu.Unlock()

	if !exists {
		writeAck(w, http.StatusNotFound, false, "unknown agent_id")
		return
	}
	writeAck(w, http.StatusOK, true, "")
}

func (a *App) AgentStatus(w http.ResponseWriter, r *http.Request, agentID string) {
	req, ok := decodeJSON[controlplaneapi.AgentStatusRequest](w, r)
	if !ok {
		return
	}

	a.mu.Lock()
	rec, exists := a.agents[agentID]
	if exists {
		rec.Status = string(req.Status)
	}
	a.mu.Unlock()

	if !exists {
		writeAck(w, http.StatusNotFound, false, "unknown agent_id")
		return
	}
	writeAck(w, http.StatusOK, true, "")
}

func (a *App) AgentDeployed(w http.ResponseWriter, r *http.Request, agentID string) {
	req, ok := decodeJSON[controlplaneapi.AgentDeployedRequest](w, r)
	if !ok {
		return
	}

	a.mu.Lock()
	rec, exists := a.agents[agentID]
	if exists {
		rec.Status = string(controlplaneapi.Deployed)
		rec.DeploymentID = req.DeploymentId
		rec.DeployedApp = req.AppName
	}
	a.mu.Unlock()

	if !exists {
		writeAck(w, http.StatusNotFound, false, "unknown agent_id")
		return
	}
	writeAck(w, http.StatusOK, true, "")
}

func (a *App) PublishAppVersion(w http.ResponseWriter, r *http.Request, appName string) {
	req, ok := decodeJSON[controlplaneapi.PublishVersionRequest](w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, controlplaneapi.PublishVersionResponse{
		VersionId: fmt.Sprintf("%s:%s", sanitizeID(appName), sanitizeID(req.Version)),
		Status:    controlplaneapi.Pending,
	})
}

func (a *App) DeployPreflight(w http.ResponseWriter, r *http.Request, _ string, _ string) {
	req, ok := decodeJSON[controlplaneapi.DeployPreflightRequest](w, r)
	if !ok {
		return
	}
	resp := controlplaneapi.DeployPreflightResponse{Eligible: true, Issues: []controlplaneapi.PlacementIssue{}}
	if req.AllowedDatacenters != nil && len(*req.AllowedDatacenters) > 0 {
		resp.SelectedDatacenter = &(*req.AllowedDatacenters)[0]
	}
	agentID := "agent-none"
	a.mu.Lock()
	for id := range a.agents {
		agentID = id
		break
	}
	a.mu.Unlock()
	resp.SelectedAgentId = &agentID
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) DeployVersion(w http.ResponseWriter, r *http.Request, appName string, version string) {
	if _, ok := decodeJSON[controlplaneapi.DeployRequest](w, r); !ok {
		return
	}
	svc := fmt.Sprintf("https://%s.%s.example", sanitizeID(appName), sanitizeID(version))
	agentID := "agent-none"
	a.mu.Lock()
	for id := range a.agents {
		agentID = id
		break
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, controlplaneapi.DeployResponse{
		DeploymentId: fmt.Sprintf("dep-%d", time.Now().UnixNano()),
		AgentId:      agentID,
		ServiceUrl:   &svc,
	})
}

func (a *App) GetDatacenterDesiredState(w http.ResponseWriter, _ *http.Request, dcID string) {
	writeJSON(w, http.StatusOK, controlplaneapi.DatacenterDesiredStateResponse{
		DcId:        dcID,
		Sequence:    1,
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) PostDatacenterEvents(w http.ResponseWriter, r *http.Request, _ string) {
	if _, ok := decodeJSON[controlplaneapi.DatacenterEventBatch](w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, controlplaneapi.AckResponse{Ok: true})
}

func (a *App) PostDatacenterSnapshot(w http.ResponseWriter, r *http.Request, _ string) {
	if _, ok := decodeJSON[controlplaneapi.DatacenterSnapshot](w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, controlplaneapi.AckResponse{Ok: true})
}
