package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// TLSConfig holds TLS configuration options for connecting to Elasticsearch/OpenSearch.
type TLSConfig struct {
	// CACertPath is the path to the CA certificate file.
	// If specified, the CA will be used to verify the server certificate.
	CACertPath string

	// ClientCertPath is the path to the client certificate file (optional).
	// If specified along with ClientKeyPath, mutual TLS authentication will be used.
	ClientCertPath string

	// ClientKeyPath is the path to the client private key file (optional).
	// Required if ClientCertPath is specified.
	ClientKeyPath string

	// SkipVerify disables server certificate verification.
	// This should only be used in development/testing environments.
	SkipVerify bool
}

// NewHTTPTransport creates an http.RoundTripper with TLS configuration.
// It returns an http.Transport configured with the specified TLS settings.
//
// If no TLS configuration is provided (all fields empty/false), it returns
// a clone of http.DefaultTransport.
//
// Example:
//
//	transport, err := config.NewHTTPTransport(config.TLSConfig{
//	    CACertPath: "/etc/opensearch/certs/root-ca.pem",
//	    SkipVerify: false,
//	})
//	if err != nil {
//	    return err
//	}
func NewHTTPTransport(tlsCfg TLSConfig) (http.RoundTripper, error) {
	// Check for mismatched client cert/key specification early
	if (tlsCfg.ClientCertPath != "" && tlsCfg.ClientKeyPath == "") ||
		(tlsCfg.ClientCertPath == "" && tlsCfg.ClientKeyPath != "") {
		return nil, fmt.Errorf("both ClientCertPath and ClientKeyPath must be specified for mutual TLS")
	}

	// Start with http.DefaultTransport clone
	transport := http.DefaultTransport.(*http.Transport).Clone()

	// If no TLS config specified, return default transport
	if tlsCfg.CACertPath == "" && !tlsCfg.SkipVerify &&
		tlsCfg.ClientCertPath == "" {
		return transport, nil
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: tlsCfg.SkipVerify,
	}

	// Load CA certificate if specified
	if tlsCfg.CACertPath != "" {
		caCert, err := os.ReadFile(tlsCfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert from %s: %w", tlsCfg.CACertPath, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", tlsCfg.CACertPath)
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if specified
	if tlsCfg.ClientCertPath != "" && tlsCfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.ClientCertPath, tlsCfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

// BasicAuthTransport wraps an http.RoundTripper and adds Basic Authentication headers
// to all outgoing requests.
//
// This transport implements the http.RoundTripper interface and can be chained with
// other transports. It's designed to work with the TLS transport created by NewHTTPTransport.
//
// Example:
//
//	tlsTransport, _ := config.NewHTTPTransport(tlsCfg)
//	authTransport := &config.BasicAuthTransport{
//	    Username:  "admin",
//	    Password:  "password",
//	    Transport: tlsTransport,
//	}
//	client := &http.Client{Transport: authTransport}
type BasicAuthTransport struct {
	// Username for basic authentication
	Username string

	// Password for basic authentication
	Password string

	// Transport is the underlying http.RoundTripper.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface.
// It adds Basic Authentication headers to the request and forwards it to the underlying transport.
func (t *BasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use default transport if none specified
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	// Clone request to avoid modifying the original
	req2 := new(http.Request)
	*req2 = *req
	req2.Header = make(http.Header, len(req.Header))
	for k, v := range req.Header {
		req2.Header[k] = v
	}

	// Set basic auth header
	req2.SetBasicAuth(t.Username, t.Password)

	// Use underlying transport
	return transport.RoundTrip(req2)
}
