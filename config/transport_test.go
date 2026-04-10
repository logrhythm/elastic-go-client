package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPTransport_Default(t *testing.T) {
	// Empty config should return default transport
	transport, err := NewHTTPTransport(TLSConfig{})
	if err != nil {
		t.Fatalf("NewHTTPTransport() with empty config failed: %v", err)
	}
	if transport == nil {
		t.Fatal("expected transport, got nil")
	}

	// Verify it's an *http.Transport
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	// Clone of DefaultTransport may have TLSClientConfig, but it should be default state
	// The important thing is that InsecureSkipVerify is false and RootCAs is nil
	if httpTransport.TLSClientConfig != nil {
		if httpTransport.TLSClientConfig.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be false for default transport")
		}
		if httpTransport.TLSClientConfig.RootCAs != nil {
			t.Error("expected RootCAs to be nil for default transport")
		}
	}
}

func TestNewHTTPTransport_SkipVerify(t *testing.T) {
	transport, err := NewHTTPTransport(TLSConfig{
		SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPTransport() with SkipVerify failed: %v", err)
	}

	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	if !httpTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestNewHTTPTransport_InvalidCAPath(t *testing.T) {
	_, err := NewHTTPTransport(TLSConfig{
		CACertPath: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Error("expected error for nonexistent CA cert path")
	}
}

func TestNewHTTPTransport_OnlyCertPathSpecified(t *testing.T) {
	_, err := NewHTTPTransport(TLSConfig{
		ClientCertPath: "/path/to/cert.pem",
		// ClientKeyPath not specified
	})
	if err == nil {
		t.Error("expected error when only cert path specified without key path")
	}
}

func TestNewHTTPTransport_OnlyKeyPathSpecified(t *testing.T) {
	_, err := NewHTTPTransport(TLSConfig{
		ClientKeyPath: "/path/to/key.pem",
		// ClientCertPath not specified
	})
	if err == nil {
		t.Error("expected error when only key path specified without cert path")
	}
}

func TestBasicAuthTransport_AddsAuthHeader(t *testing.T) {
	// Create mock server that verifies auth header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("expected basic auth header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if user != "testuser" || pass != "testpass" {
			t.Errorf("got user=%s pass=%s, want testuser/testpass", user, pass)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create auth transport
	transport := &BasicAuthTransport{
		Username:  "testuser",
		Password:  "testpass",
		Transport: http.DefaultTransport,
	}

	// Make request with auth transport
	client := &http.Client{Transport: transport}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestBasicAuthTransport_DefaultTransport(t *testing.T) {
	// Test that nil Transport uses http.DefaultTransport
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &BasicAuthTransport{
		Username: "user",
		Password: "pass",
		// Transport: nil (should use default)
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestBasicAuthTransport_PreservesHeaders(t *testing.T) {
	// Verify that auth transport preserves existing headers
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-Header") != "test-value" {
			t.Error("custom header not preserved")
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("user-agent header not preserved")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &BasicAuthTransport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("X-Custom-Header", "test-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
}

func TestBasicAuthTransport_Chaining(t *testing.T) {
	// Test chaining BasicAuth with custom TLS transport
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			t.Error("auth not applied correctly in chain")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create TLS transport with skip verify (for test server)
	tlsTransport, err := NewHTTPTransport(TLSConfig{
		SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPTransport failed: %v", err)
	}

	// Chain with basic auth
	authTransport := &BasicAuthTransport{
		Username:  "admin",
		Password:  "secret",
		Transport: tlsTransport,
	}

	client := &http.Client{Transport: authTransport}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestNewHTTPTransport_TLSVersions(t *testing.T) {
	// Test that the transport uses modern TLS by default
	transport, err := NewHTTPTransport(TLSConfig{
		SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPTransport failed: %v", err)
	}

	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	// The TLS config should be set
	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	// MinVersion should be 0 (uses Go's default, which is TLS 1.2+)
	if httpTransport.TLSClientConfig.MinVersion != 0 {
		t.Logf("Note: MinVersion is %d (0 means use Go default)", httpTransport.TLSClientConfig.MinVersion)
	}
}

// TestBasicAuthTransport_RequestNotModified verifies that the original request is not modified
func TestBasicAuthTransport_RequestNotModified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &BasicAuthTransport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", ts.URL, nil)

	// Original request should not have auth header
	if req.Header.Get("Authorization") != "" {
		t.Error("original request should not have Authorization header before request")
	}

	_, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Original request should still not have auth header
	if req.Header.Get("Authorization") != "" {
		t.Error("original request should not have Authorization header after request")
	}
}

// Benchmark tests
func BenchmarkBasicAuthTransport(b *testing.B) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &BasicAuthTransport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(ts.URL)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkNewHTTPTransport(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewHTTPTransport(TLSConfig{
			SkipVerify: true,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
