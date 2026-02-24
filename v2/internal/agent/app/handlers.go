package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/easyenclave/easyenclave/v2/internal/gen/agentapi"
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
		writeJSON(w, http.StatusBadRequest, agentapi.AckResponse{Ok: false, Message: ptr("invalid json")})
		return nil, false
	}
	return &out, true
}

func ptr[T any](v T) *T { return &v }

func (a *App) GetAgentHealth(w http.ResponseWriter, _ *http.Request) {
	attested := true
	writeJSON(w, http.StatusOK, agentapi.AgentHealthResponse{
		Status:   agentapi.Ok,
		Service:  "agent-v2-" + version.Version,
		Attested: &attested,
	})
}

func (a *App) GetControlChallenge(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentapi.ControlChallengeResponse{
		Nonce:     fmt.Sprintf("agent-%d", time.Now().UnixNano()),
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
}

func (a *App) DeployWorkload(w http.ResponseWriter, r *http.Request) {
	if _, ok := decodeJSON[agentapi.DeployWorkloadRequest](w, r); !ok {
		return
	}
	msg := "deploy accepted"
	writeJSON(w, http.StatusOK, agentapi.AckResponse{Ok: true, Message: &msg})
}

func (a *App) UndeployWorkload(w http.ResponseWriter, r *http.Request) {
	if _, ok := decodeJSON[agentapi.UndeployWorkloadRequest](w, r); !ok {
		return
	}
	msg := "undeploy accepted"
	writeJSON(w, http.StatusOK, agentapi.AckResponse{Ok: true, Message: &msg})
}

func (a *App) GetAgentLogs(w http.ResponseWriter, _ *http.Request, params agentapi.GetAgentLogsParams) {
	_ = params
	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, agentapi.LogsResponse{
		Logs: []struct {
			Level     string    `json:"level"`
			Message   string    `json:"message"`
			Timestamp time.Time `json:"timestamp"`
		}{
			{Level: "INFO", Message: "agent started", Timestamp: now},
		},
	})
}

func (a *App) GetAgentStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentapi.StatsResponse{
		CpuUsage:         0.01,
		MemoryUsageBytes: 64 * 1024 * 1024,
	})
}

func (a *App) GetAgentStateSnapshot(w http.ResponseWriter, _ *http.Request) {
	health := agentapi.Healthy
	writeJSON(w, http.StatusOK, agentapi.StateSnapshotResponse{
		Health:     health,
		ObservedAt: time.Now().UTC(),
	})
}
