package internal

import (
	"encoding/hex"
	"errors"
	"fmt"
	tls "github.com/bogdanfinn/utls"
	"strings"
)

func sanitizeFingerprint(fingerprint string) string {
	if fingerprint == "Default" {
		return ""
	}

	parts := strings.Split(fingerprint, " ")

	for i, part := range parts {
		sanitized := strings.TrimSpace(part)
		if i == 0 {
			sanitized = strings.ToLower(sanitized)
		}
		sanitized = strings.ReplaceAll(sanitized, ".", "_")
		parts[i] = sanitized
	}

	return strings.Join(parts, "_")
}

func rawToSpec(hexClientHello string) (*tls.ClientHelloSpec, error) {
	if hexClientHello == "" {
		return nil, errors.New("empty client hello")
	}

	raw, err := hex.DecodeString(hexClientHello)
	if err != nil {
		return nil, fmt.Errorf("decode hexClientHello: %w", err)
	}

	fingerprinter := tls.Fingerprinter{}
	spec, err := fingerprinter.RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("FingerprintClientHello: %w", err)
	}

	return spec, nil
}
