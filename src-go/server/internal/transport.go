package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"net"
	"strings"
	"time"
)

type TransportConfig struct {
	// Hostname to send the HTTP request to.
	Host string

	// HTTP or HTTPs.
	Scheme string

	// The TLS fingerprint to use.
	Fingerprint string

	// Custom Client Hello to use.
	// This is a hex-encoded string.
	HexClientHello string

	// The maximum amount of time a dial will wait for a connect to complete.
	// Defaults to 30 seconds.
	HttpTimeout int

	// Specifies the interval between keep-alive probes for an active network connection.
	// Defaults to 30 seconds.
	HttpKeepAliveInterval int

	// The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself.
	// Defaults to 90 seconds.
	IdleConnTimeout int
}

func NewTransportConfig(serializedJson string) (*TransportConfig, error) {
	config := &TransportConfig{}

	if strings.TrimSpace(serializedJson) == "" {
		return nil, errors.New("missing transport configuration")
	}

	if err := json.Unmarshal([]byte(serializedJson), config); err != nil {
		return nil, err
	}

	return config, nil
}

// NewClient creates a new http/tls client using the given configuration.
func NewClient(config *TransportConfig) (tlsclient.HttpClient, error) {
	dialer := net.Dialer{
		Timeout:   time.Duration(30) * time.Second,
		KeepAlive: time.Duration(30) * time.Second,
	}
	if config.HttpTimeout != 0 {
		dialer.Timeout = time.Duration(config.HttpTimeout) * time.Second
	}
	if config.HttpKeepAliveInterval != 0 {
		dialer.KeepAlive = time.Duration(config.HttpKeepAliveInterval) * time.Second
	}

	defaultIdleConnTimeout := time.Duration(90) * time.Second
	transportOptions := &tlsclient.TransportOptions{
		MaxIdleConns:    100,
		IdleConnTimeout: &defaultIdleConnTimeout,
	}
	if config.IdleConnTimeout != 0 {
		idleConnTimeout := time.Duration(config.IdleConnTimeout) * time.Second
		transportOptions.IdleConnTimeout = &idleConnTimeout
	}

	var clientProfile profiles.ClientProfile
	if config.HexClientHello != "" {
		clientProfile = profiles.NewClientProfile(tls.ClientHelloID{
			Client:  "custom",
			Version: "1",
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				spec, err := rawToSpec(config.HexClientHello)
				if err != nil {
					return tls.ClientHelloSpec{}, fmt.Errorf("failed to create spec from client hello: %w", err)
				}
				return *spec, nil
			},
		}, nil, nil, nil, 0, nil, nil)
	} else if p, ok := profiles.MappedTLSClients[sanitizeFingerprint(config.Fingerprint)]; ok {
		clientProfile = p
	} else {
		clientProfile = profiles.DefaultClientProfile
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithDialer(dialer),
		tlsclient.WithTransportOptions(transportOptions),
		tlsclient.WithClientProfile(clientProfile),
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %w", err)
	}

	return client, nil
}
