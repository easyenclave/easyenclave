package tdxquote

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseQuoteB64(t *testing.T) {
	quote := make([]byte, minQuoteSize)
	quote[0] = 0x03
	quote[1] = 0x00

	fill(quote[mrtdOffset:mrtdOffset+mrtdLength], 0x11)
	fill(quote[rtmr0Offset:rtmr0Offset+rtmrMeasurementLength], 0x22)
	fill(quote[rtmr0Offset+48:rtmr0Offset+96], 0x33)
	fill(quote[rtmr0Offset+96:rtmr0Offset+144], 0x44)
	fill(quote[rtmr0Offset+144:rtmr0Offset+192], 0x55)

	wantPrefix := hex.EncodeToString([]byte("nonce-abc"))
	copy(quote[reportDataOffset:reportDataOffset+64], append([]byte("nonce-abc"), make([]byte, 64-len("nonce-abc"))...))

	parsed, err := ParseQuoteB64(base64.StdEncoding.EncodeToString(quote))
	if err != nil {
		t.Fatalf("ParseQuoteB64: %v", err)
	}
	if parsed.Version != 3 {
		t.Fatalf("version=%d want=3", parsed.Version)
	}
	if !strings.HasPrefix(parsed.ReportData, wantPrefix) {
		t.Fatalf("report_data prefix mismatch: got=%s wantPrefix=%s", parsed.ReportData, wantPrefix)
	}
	if parsed.MRTD != strings.Repeat("11", mrtdLength) {
		t.Fatalf("unexpected mrtd: %s", parsed.MRTD)
	}
}

func TestParseQuoteB64Errors(t *testing.T) {
	if _, err := ParseQuoteB64("not-b64"); err == nil {
		t.Fatalf("expected invalid base64 error")
	}
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	if _, err := ParseQuoteB64(short); err == nil {
		t.Fatalf("expected quote too short error")
	}
}

func fill(dst []byte, val byte) {
	for i := range dst {
		dst[i] = val
	}
}
