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
	req, ok := decodeJSON[agentapi.DeployWorkloadRequest](w, r)
	if !ok {
		return
	}
	a.deployedApp.Store(req.AppName)
	a.deploymentID.Store(req.DeploymentId)
	a.heartbeatSeq.Add(1)
	msg := "deploy accepted"
	writeJSON(w, http.StatusOK, agentapi.AckResponse{Ok: true, Message: &msg})
}

func (a *App) UndeployWorkload(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[agentapi.UndeployWorkloadRequest](w, r)
	if !ok {
		return
	}
	currentDeploymentID, _ := a.deploymentID.Load().(string)
	if currentDeploymentID != "" && req.DeploymentId != "" && currentDeploymentID != req.DeploymentId {
		msg := "deployment_id mismatch"
		writeJSON(w, http.StatusConflict, agentapi.AckResponse{Ok: false, Message: &msg})
		return
	}
	a.deployedApp.Store("")
	a.deploymentID.Store("")
	a.heartbeatSeq.Add(1)
	msg := "undeploy accepted"
	writeJSON(w, http.StatusOK, agentapi.AckResponse{Ok: true, Message: &msg})
}

func (a *App) GetAgentLogs(w http.ResponseWriter, _ *http.Request, params agentapi.GetAgentLogsParams) {
	_ = params
	now := time.Now().UTC()
	deployedApp, _ := a.deployedApp.Load().(string)
	msg := "agent started"
	if deployedApp != "" {
		msg = "agent deployed app " + deployedApp
	}
	writeJSON(w, http.StatusOK, agentapi.LogsResponse{
		Logs: []struct {
			Level     string    `json:"level"`
			Message   string    `json:"message"`
			Timestamp time.Time `json:"timestamp"`
		}{
			{Level: "INFO", Message: msg, Timestamp: now},
		},
	})
}

func (a *App) GetAgentStats(w http.ResponseWriter, _ *http.Request) {
	deployedApp, _ := a.deployedApp.Load().(string)
	deploymentID, _ := a.deploymentID.Load().(string)

	writeJSON(w, http.StatusOK, agentapi.StatsResponse{
		CpuUsage:         0.01,
		MemoryUsageBytes: 64 * 1024 * 1024,
		DeployedApp:      stringPtrOrNil(deployedApp),
		DeploymentId:     stringPtrOrNil(deploymentID),
	})
}

func (a *App) GetAgentStateSnapshot(w http.ResponseWriter, _ *http.Request) {
	deployedApp, _ := a.deployedApp.Load().(string)
	deploymentID, _ := a.deploymentID.Load().(string)

	health := agentapi.Healthy
	seq := a.heartbeatSeq.Load()
	var workload *map[string]interface{}
	if deployedApp != "" || deploymentID != "" {
		w := map[string]interface{}{
			"app_name":      deployedApp,
			"deployment_id": deploymentID,
		}
		workload = &w
	}

	labels := map[string]string{
		"datacenter": a.cfg.Datacenter,
		"node_size":  a.cfg.NodeSize,
		"vm_name":    a.cfg.VMName,
	}
	for k, v := range a.cfg.SchedulerLabels {
		labels[k] = v
	}

	writeJSON(w, http.StatusOK, agentapi.StateSnapshotResponse{
		Health:           health,
		ObservedAt:       time.Now().UTC(),
		DeployedWorkload: workload,
		HeartbeatSeq:     &seq,
		SchedulerLabels:  &labels,
	})
}

func stringPtrOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
