// Connect with TLS demonstrates how to connect to Elasticsearch/OpenSearch
// with TLS certificates and Basic Authentication.
//
// This recipe shows two approaches:
// 1. Using Config with URL parsing
// 2. Using transport chaining for more control
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	elastic "github.com/logrhythm/elastic-go-client"
	"github.com/logrhythm/elastic-go-client/config"
)

func main() {
	// Example 1: Using Config with URL parsing
	fmt.Println("Example 1: Using Config URL parsing")
	example1()

	// Example 2: Using transport chaining
	fmt.Println("\nExample 2: Using transport chaining")
	example2()
}

// example1 demonstrates using Config with URL query parameters for TLS
func example1() {
	// Parse URL with TLS and auth parameters
	cfg, err := config.Parse(
		"https://admin:admin@localhost:9200?" +
			"cacert=/etc/opensearch/certs/root-ca.pem&" +
			"sniff=false",
	)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Create client from config
	client, err := elastic.NewClientFromConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Test connection
	info, code, err := client.Ping("https://localhost:9200").Do(context.Background())
	if err != nil {
		log.Printf("Ping failed: %v", err)
		return
	}

	fmt.Printf("Elasticsearch version %s (code: %d)\n", info.Version.Number, code)
}

// example2 demonstrates manual transport chaining for more control
func example2() {
	// Create TLS transport with CA certificate
	transport, err := config.NewHTTPTransport(config.TLSConfig{
		CACertPath: "/etc/opensearch/certs/root-ca.pem",
		SkipVerify: false, // Set to true for development with self-signed certs
	})
	if err != nil {
		log.Fatalf("Failed to create TLS transport: %v", err)
	}

	// Wrap with Basic Auth
	authTransport := &config.BasicAuthTransport{
		Username:  "admin",
		Password:  "admin",
		Transport: transport,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Transport: authTransport,
	}

	// Create Elasticsearch client
	client, err := elastic.NewClient(
		elastic.SetURL("https://localhost:9200"),
		elastic.SetHttpClient(httpClient),
		elastic.SetSniff(false),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Test connection
	info, code, err := client.Ping("https://localhost:9200").Do(context.Background())
	if err != nil {
		log.Printf("Ping failed: %v", err)
		return
	}

	fmt.Printf("Elasticsearch version %s (code: %d)\n", info.Version.Number, code)
}

// For development/testing with self-signed certificates,
// you can use TLSSkipVerify:
func exampleWithSkipVerify() {
	transport, err := config.NewHTTPTransport(config.TLSConfig{
		SkipVerify: true, // WARNING: Only use in development!
	})
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	authTransport := &config.BasicAuthTransport{
		Username:  "admin",
		Password:  "admin",
		Transport: transport,
	}

	client, err := elastic.NewClient(
		elastic.SetURL("https://localhost:9200"),
		elastic.SetHttpClient(&http.Client{Transport: authTransport}),
		elastic.SetSniff(false),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Printf("Client created: %v\n", client)
}

// For mutual TLS (client certificate authentication):
func exampleWithMutualTLS() {
	transport, err := config.NewHTTPTransport(config.TLSConfig{
		CACertPath:     "/etc/opensearch/certs/root-ca.pem",
		ClientCertPath: "/etc/opensearch/certs/client.pem",
		ClientKeyPath:  "/etc/opensearch/certs/client-key.pem",
	})
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	// Note: Basic auth may not be needed with client certificates
	client, err := elastic.NewClient(
		elastic.SetURL("https://localhost:9200"),
		elastic.SetHttpClient(&http.Client{Transport: transport}),
		elastic.SetSniff(false),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Printf("Client created with mutual TLS: %v\n", client)
}
