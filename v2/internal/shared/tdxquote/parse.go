package tdxquote

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	headerSize            = 48
	tdReportSize          = 584
	minQuoteSize          = headerSize + tdReportSize
	mrtdOffset            = headerSize + 136
	rtmr0Offset           = headerSize + 328
	rtmrMeasurementLength = 48
	mrtdLength            = 48
	reportDataOffset      = headerSize + 520
	reportDataLength      = 64
)

var (
	ErrInvalidBase64 = errors.New("invalid base64 quote")
	ErrQuoteTooShort = errors.New("quote too short")
)

type Parsed struct {
	QuoteSize  int    `json:"quote_size"`
	Version    uint16 `json:"version"`
	MRTD       string `json:"mrtd"`
	RTMR0      string `json:"rtmr0"`
	RTMR1      string `json:"rtmr1"`
	RTMR2      string `json:"rtmr2"`
	RTMR3      string `json:"rtmr3"`
	ReportData string `json:"report_data"`
}

func ParseQuoteB64(quoteB64 string) (Parsed, error) {
	raw, err := decodeQuoteB64(quoteB64)
	if err != nil {
		return Parsed{}, err
	}
	return ParseQuote(raw)
}

func ParseQuote(raw []byte) (Parsed, error) {
	if len(raw) < minQuoteSize {
		return Parsed{}, fmt.Errorf("%w: got=%d need>=%d", ErrQuoteTooShort, len(raw), minQuoteSize)
	}

	parsed := Parsed{
		QuoteSize:  len(raw),
		Version:    uint16(raw[0]) | uint16(raw[1])<<8,
		MRTD:       hex.EncodeToString(raw[mrtdOffset : mrtdOffset+mrtdLength]),
		RTMR0:      hex.EncodeToString(raw[rtmr0Offset : rtmr0Offset+rtmrMeasurementLength]),
		RTMR1:      hex.EncodeToString(raw[rtmr0Offset+48 : rtmr0Offset+48+rtmrMeasurementLength]),
		RTMR2:      hex.EncodeToString(raw[rtmr0Offset+96 : rtmr0Offset+96+rtmrMeasurementLength]),
		RTMR3:      hex.EncodeToString(raw[rtmr0Offset+144 : rtmr0Offset+144+rtmrMeasurementLength]),
		ReportData: hex.EncodeToString(raw[reportDataOffset : reportDataOffset+reportDataLength]),
	}
	return parsed, nil
}

func (p Parsed) JSON() string {
	buf, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func decodeQuoteB64(in string) ([]byte, error) {
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range decoders {
		raw, err := enc.DecodeString(in)
		if err == nil {
			return raw, nil
		}
	}
	return nil, ErrInvalidBase64
}
