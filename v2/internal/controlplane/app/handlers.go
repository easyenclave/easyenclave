package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/easyenclave/easyenclave/v2/internal/gen/controlplaneapi"
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

func (a *App) GetControlPlaneHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, controlplaneapi.HealthResponse{
		Status:  controlplaneapi.Ok,
		Service: "control-plane-v2",
		Version: ptr(version.Version),
	})
}

func (a *App) GetAgentChallenge(w http.ResponseWriter, _ *http.Request, params controlplaneapi.GetAgentChallengeParams) {
	nonce := fmt.Sprintf("cp-%s-%d", sanitizeID(params.VmName), time.Now().UnixNano())
	writeJSON(w, http.StatusOK, controlplaneapi.ChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
}

func (a *App) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[controlplaneapi.AgentRegisterRequest](w, r)
	if !ok {
		return
	}
	mode := controlplaneapi.Direct
	writeJSON(w, http.StatusOK, controlplaneapi.AgentRegisterResponse{
		AgentId:        "agent-" + sanitizeID(req.VmName),
		AgentApiSecret: "dev-secret-" + sanitizeID(req.VmName),
		Mode:           &mode,
	})
}

func (a *App) AgentHeartbeat(w http.ResponseWriter, r *http.Request, _ string) {
	if _, ok := decodeJSON[controlplaneapi.HeartbeatRequest](w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, controlplaneapi.AckResponse{Ok: true})
}

func (a *App) AgentStatus(w http.ResponseWriter, r *http.Request, _ string) {
	if _, ok := decodeJSON[controlplaneapi.AgentStatusRequest](w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, controlplaneapi.AckResponse{Ok: true})
}

func (a *App) AgentDeployed(w http.ResponseWriter, r *http.Request, _ string) {
	if _, ok := decodeJSON[controlplaneapi.AgentDeployedRequest](w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, controlplaneapi.AckResponse{Ok: true})
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
	agentID := "agent-placeholder"
	resp.SelectedAgentId = &agentID
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) DeployVersion(w http.ResponseWriter, r *http.Request, appName string, version string) {
	if _, ok := decodeJSON[controlplaneapi.DeployRequest](w, r); !ok {
		return
	}
	svc := fmt.Sprintf("https://%s.%s.example", sanitizeID(appName), sanitizeID(version))
	writeJSON(w, http.StatusOK, controlplaneapi.DeployResponse{
		DeploymentId: fmt.Sprintf("dep-%d", time.Now().UnixNano()),
		AgentId:      "agent-placeholder",
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
