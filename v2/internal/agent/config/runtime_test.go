package config

import (
	"os"
	"testing"
)

func TestToRuntimeResolvesDatacenterAndNodeSize(t *testing.T) {
	t.Setenv("EASYENCLAVE_DEFAULT_SIZE", "tiny")
	cfg := map[string]any{
		"mode":              "agent",
		"cloud_provider":    "gcp",
		"availability_zone": "us-central1-a",
		"node_size":         "llm",
		"vm_id":             "vm-123",
	}
	rt := ToRuntime(cfg)
	if rt.Datacenter != "gcp:us-central1-a" {
		t.Fatalf("datacenter=%s", rt.Datacenter)
	}
	if rt.NodeSize != "llm" {
		t.Fatalf("node_size=%s", rt.NodeSize)
	}
	if rt.VMName != "vm-123" {
		t.Fatalf("vm_name=%s", rt.VMName)
	}
}

func TestToRuntimeDefaults(t *testing.T) {
	t.Setenv("VM_NAME", "")
	t.Setenv("EASYENCLAVE_DEFAULT_SIZE", "")
	t.Setenv("EASYENCLAVE_DEFAULT_DATACENTER", "")
	rt := ToRuntime(map[string]any{})
	if rt.NodeSize != "tiny" {
		t.Fatalf("node_size=%s", rt.NodeSize)
	}
	if rt.Datacenter != "baremetal:default" {
		t.Fatalf("datacenter=%s", rt.Datacenter)
	}
	if rt.VMName == "" {
		t.Fatalf("expected non-empty vm_name")
	}
}

func TestToRuntimeUsesVMNameEnv(t *testing.T) {
	t.Setenv("VM_NAME", "forced-vm")
	rt := ToRuntime(map[string]any{"vm_name": "other"})
	if rt.VMName != "forced-vm" {
		t.Fatalf("vm_name=%s", rt.VMName)
	}
}

func TestResolveDatacenterFallbackEnv(t *testing.T) {
	os.Setenv("EASYENCLAVE_DEFAULT_DATACENTER", "gcp:us-central1")
	t.Cleanup(func() { _ = os.Unsetenv("EASYENCLAVE_DEFAULT_DATACENTER") })
	rt := ToRuntime(map[string]any{})
	if rt.Datacenter != "gcp:us-central1" {
		t.Fatalf("datacenter=%s", rt.Datacenter)
	}
}
