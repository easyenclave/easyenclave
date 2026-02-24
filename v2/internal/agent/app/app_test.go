package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easyenclave/easyenclave/v2/internal/gen/agentapi"
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

func TestDeployUpdatesSnapshot(t *testing.T) {
	a, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	deployBody := agentapi.DeployWorkloadRequest{
		DeploymentId: "dep-1",
		AppName:      "echo",
		Version:      "v1",
	}
	raw, err := json.Marshal(deployBody)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	deployReq := httptest.NewRequest(http.MethodPost, "/api/v2/deploy", bytes.NewReader(raw))
	deployResp := httptest.NewRecorder()
	a.Handler().ServeHTTP(deployResp, deployReq)
	if deployResp.Code != http.StatusOK {
		t.Fatalf("deploy status=%d body=%s", deployResp.Code, deployResp.Body.String())
	}

	snapReq := httptest.NewRequest(http.MethodGet, "/api/v2/state-snapshot", nil)
	snapResp := httptest.NewRecorder()
	a.Handler().ServeHTTP(snapResp, snapReq)
	if snapResp.Code != http.StatusOK {
		t.Fatalf("snapshot status=%d", snapResp.Code)
	}
	var snapshot agentapi.StateSnapshotResponse
	if err := json.NewDecoder(snapResp.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snapshot.DeployedWorkload == nil {
		t.Fatalf("expected deployed workload in snapshot")
	}
	if snapshot.HeartbeatSeq == nil || *snapshot.HeartbeatSeq == 0 {
		t.Fatalf("expected heartbeat_seq > 0")
	}
}
