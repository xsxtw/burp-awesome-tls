package server

import (
	"context"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	tls "github.com/bogdanfinn/utls"
	"io"
	"net"
	"net/url"
	"server/internal"
)

// DefaultAddress is the default listener address.
const DefaultAddress string = "127.0.0.1:8887"

// ConfigurationHeaderKey is the name of the header field that contains the RoundTripper configuration.
// Note that this key can only start with one capital letter and the rest in lowercase.
// Unfortunately, this seems to be a limitation of Burp's Extender API.
const ConfigurationHeaderKey = "Awesometlsconfig"

var s *http.Server

func init() {
	s = &http.Server{}
}

func StartServer(addr string) error {
	ca, private, err := NewCertificateAuthority()
	if err != nil {
		return err
	}

	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, burpReq *http.Request) {
		// TODO: fix req and res header order (Java side probably needs to specify the order now and the loc below probably doesn't work anymore because nothing actually sets the order)
		http.EnableHeaderOrder(w)

		configHeader := burpReq.Header.Get(ConfigurationHeaderKey)
		burpReq.Header.Del(ConfigurationHeaderKey)

		config, err := internal.NewTransportConfig(configHeader)
		if err != nil {
			writeError(w, err)
			return
		}

		client, err := internal.NewClient(config)
		if err != nil {
			writeError(w, err)
			return
		}

		req := &http.Request{
			URL: &url.URL{
				Scheme:      config.Scheme,
				Host:        config.Host,
				Opaque:      burpReq.URL.Opaque,
				User:        burpReq.URL.User,
				Path:        burpReq.URL.Path,
				RawPath:     burpReq.URL.RawPath,
				OmitHost:    burpReq.URL.OmitHost,
				ForceQuery:  burpReq.URL.ForceQuery,
				RawQuery:    burpReq.URL.RawQuery,
				Fragment:    burpReq.URL.Fragment,
				RawFragment: burpReq.URL.RawFragment,
			},
			Method: burpReq.Method,
			Header: burpReq.Header,
			Body:   burpReq.Body,
		}

		res, err := client.Do(req)
		if err != nil {
			writeError(w, err)
			return
		}

		defer res.Body.Close()

		// Write the response (back to burp).
		res.Header.Del("Content-Length")
		for k := range res.Header {
			vv := res.Header.Values(k)
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(res.StatusCode)

		body, err := io.ReadAll(res.Body)
		if err != nil {
			writeError(w, err)
			return
		}

		_, err = w.Write(body)
		if err != nil {
			writeError(w, err)
			return
		}
	})

	s.Addr = addr
	s.Handler = m
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{ca.Raw},
				PrivateKey:  private,
				Leaf:        ca,
			},
		},
		NextProtos: []string{"http/1.1", "h2"},
	}

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(listener, s.TLSConfig)

	return s.Serve(tlsListener)
}

func StopServer() error {
	return s.Shutdown(context.Background())
}

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	fmt.Fprint(w, fmt.Errorf("Awesome TLS error: %s", err))
	fmt.Println(err)
}
