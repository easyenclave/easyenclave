package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Runtime struct {
	Mode            string
	NodeSize        string
	Datacenter      string
	VMName          string
	SchedulerLabels map[string]string
}

func ToRuntime(cfg map[string]any) Runtime {
	mode := getString(cfg, "mode")
	if mode == "" {
		mode = "agent"
	}

	nodeSize := getString(cfg, "node_size")
	if nodeSize == "" {
		nodeSize = strings.TrimSpace(os.Getenv("EASYENCLAVE_DEFAULT_SIZE"))
	}
	if nodeSize == "" {
		nodeSize = "tiny"
	}
	nodeSize = strings.ToLower(nodeSize)

	datacenter := resolveDatacenterLabel(cfg)
	vmName := resolveVMName(cfg)
	labels := map[string]string{
		"mode":       mode,
		"node_size":  nodeSize,
		"datacenter": datacenter,
		"vm_name":    vmName,
	}

	for _, key := range []string{"cloud_provider", "availability_zone", "region"} {
		if v := getString(cfg, key); v != "" {
			labels[key] = strings.ToLower(v)
		}
	}

	return Runtime{
		Mode:            mode,
		NodeSize:        nodeSize,
		Datacenter:      datacenter,
		VMName:          vmName,
		SchedulerLabels: labels,
	}
}

func resolveVMName(cfg map[string]any) string {
	if env := strings.TrimSpace(os.Getenv("VM_NAME")); env != "" {
		return env
	}
	for _, key := range []string{"vm_name", "vm_id"} {
		if v := getString(cfg, key); v != "" {
			return v
		}
	}
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return fmt.Sprintf("agent-%d", time.Now().Unix())
}

func resolveDatacenterLabel(cfg map[string]any) string {
	if explicit := strings.TrimSpace(getString(cfg, "datacenter")); explicit != "" {
		return strings.ToLower(explicit)
	}

	providerRaw := strings.ToLower(strings.TrimSpace(getString(cfg, "cloud_provider")))
	azRaw := strings.ToLower(strings.TrimSpace(firstNonEmpty(getString(cfg, "availability_zone"), getString(cfg, "zone"))))
	regionRaw := strings.ToLower(strings.TrimSpace(getString(cfg, "region")))

	provider := providerRaw
	switch providerRaw {
	case "google", "gcp":
		provider = "gcp"
	case "azure", "az":
		provider = "azure"
	case "baremetal", "bare-metal", "onprem", "on-prem", "self-hosted":
		provider = "baremetal"
	}

	if provider != "" && azRaw != "" {
		return provider + ":" + azRaw
	}
	if provider != "" && regionRaw != "" {
		return provider + ":" + regionRaw
	}
	if provider == "baremetal" {
		return "baremetal:default"
	}
	if fallback := strings.ToLower(strings.TrimSpace(os.Getenv("EASYENCLAVE_DEFAULT_DATACENTER"))); fallback != "" {
		return fallback
	}
	return "baremetal:default"
}

func getString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
