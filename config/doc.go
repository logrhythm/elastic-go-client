// Copyright 2012-present Oliver Eilhard. All rights reserved.
// Use of this source code is governed by a MIT-license.
// See http://olivere.mit-license.org/license.txt for details.

/*
Package config allows parsing a configuration for Elasticsearch
from a URL and provides TLS transport utilities.

# TLS Configuration

The config package supports TLS connections with custom CA certificates,
client certificates, and verification options:

	tlsCfg := config.TLSConfig{
		CACertPath: "/path/to/ca.pem",
		SkipVerify: false,
	}
	transport, err := config.NewHTTPTransport(tlsCfg)

# Basic Authentication

Use BasicAuthTransport to add authentication headers:

	authTransport := &config.BasicAuthTransport{
		Username:  "admin",
		Password:  "password",
		Transport: transport,
	}

	client, err := elastic.NewClient(
		elastic.SetHttpClient(&http.Client{Transport: authTransport}),
	)

# URL-based Configuration

The Parse function extracts configuration from URLs with query parameters:

	cfg, err := config.Parse(
		"https://admin:pass@localhost:9200?" +
		"cacert=/etc/certs/ca.pem&sniff=false",
	)
	client, err := elastic.NewClientFromConfig(cfg)

Supported query parameters include cacert, clientcert, clientkey, and
tlsskipverify for TLS configuration.
*/
package config
