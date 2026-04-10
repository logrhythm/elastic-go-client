// Copyright 2012-present Oliver Eilhard. All rights reserved.
// Use of this source code is governed by a MIT-license.
// See http://olivere.mit-license.org/license.txt for details.

package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Config represents an Elasticsearch configuration.
type Config struct {
	URL         string
	Index       string
	Username    string
	Password    string
	Shards      int
	Replicas    int
	Sniff       *bool
	Healthcheck *bool
	Infolog     string
	Errorlog    string
	Tracelog    string

	// TLS Configuration
	CACert        string // Path to CA certificate file
	ClientCert    string // Path to client certificate file (for mutual TLS)
	ClientKey     string // Path to client key file (for mutual TLS)
	TLSSkipVerify bool   // Skip TLS certificate verification (for development/testing)
}

// Parse returns the Elasticsearch configuration by extracting it
// from the URL, its path, and its query string.
//
// Example:
//   http://127.0.0.1:9200/store-blobs?shards=1&replicas=0&sniff=false&tracelog=elastic.trace.log
//
// TLS Configuration Example:
//   https://admin:pass@localhost:9200?cacert=/path/to/ca.pem&tlsskipverify=false
//
// The code above will return a URL of http://127.0.0.1:9200, an index name
// of store-blobs, and the related settings from the query string.
//
// Supported query parameters:
//   - shards, replicas: Index settings
//   - sniff, healthcheck: Client behavior (bool)
//   - infolog, errorlog, tracelog: Logging paths
//   - cacert, clientcert, clientkey: TLS certificate paths
//   - tlsskipverify: Skip TLS verification (bool)
func Parse(elasticURL string) (*Config, error) {
	cfg := &Config{
		Shards:   1,
		Replicas: 0,
		Sniff:    nil,
	}

	uri, err := url.Parse(elasticURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing elastic parameter %q: %v", elasticURL, err)
	}
	index := strings.TrimSuffix(strings.TrimPrefix(uri.Path, "/"), "/")
	if uri.User != nil {
		cfg.Username = uri.User.Username()
		cfg.Password, _ = uri.User.Password()
	}
	uri.User = nil

	if i, err := strconv.Atoi(uri.Query().Get("shards")); err == nil {
		cfg.Shards = i
	}
	if i, err := strconv.Atoi(uri.Query().Get("replicas")); err == nil {
		cfg.Replicas = i
	}
	if s := uri.Query().Get("sniff"); s != "" {
		if b, err := strconv.ParseBool(s); err == nil {
			cfg.Sniff = &b
		}
	}
	if s := uri.Query().Get("healthcheck"); s != "" {
		if b, err := strconv.ParseBool(s); err == nil {
			cfg.Healthcheck = &b
		}
	}
	if s := uri.Query().Get("infolog"); s != "" {
		cfg.Infolog = s
	}
	if s := uri.Query().Get("errorlog"); s != "" {
		cfg.Errorlog = s
	}
	if s := uri.Query().Get("tracelog"); s != "" {
		cfg.Tracelog = s
	}

	// Parse TLS configuration
	if s := uri.Query().Get("cacert"); s != "" {
		cfg.CACert = s
	}
	if s := uri.Query().Get("clientcert"); s != "" {
		cfg.ClientCert = s
	}
	if s := uri.Query().Get("clientkey"); s != "" {
		cfg.ClientKey = s
	}
	if s := uri.Query().Get("tlsskipverify"); s != "" {
		if b, err := strconv.ParseBool(s); err == nil {
			cfg.TLSSkipVerify = b
		}
	}

	uri.Path = ""
	uri.RawQuery = ""
	cfg.URL = uri.String()
	cfg.Index = index

	return cfg, nil
}
