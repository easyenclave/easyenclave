package root

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer

	rc := Run([]string{"version"}, &out, &errOut)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d", rc)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Fatalf("expected version output")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer

	rc := Run([]string{"nope"}, &out, &errOut)
	if rc != 2 {
		t.Fatalf("expected rc=2, got %d", rc)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("expected unknown command error")
	}
}
