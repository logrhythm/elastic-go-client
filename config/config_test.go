// Copyright 2012-present Oliver Eilhard. All rights reserved.
// Use of this source code is governed by a MIT-license.
// See http://olivere.mit-license.org/license.txt for details.

package config

import "testing"

func TestParse(t *testing.T) {
	urls := "http://user:pwd@elastic:19220/store-blobs?shards=5&replicas=2&sniff=true&healthcheck=false&errorlog=elastic.error.log&infolog=elastic.info.log&tracelog=elastic.trace.log"
	cfg, err := Parse(urls)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := "http://elastic:19220", cfg.URL; want != got {
		t.Fatalf("expected URL = %q, got %q", want, got)
	}
	if want, got := "store-blobs", cfg.Index; want != got {
		t.Fatalf("expected Index = %q, got %q", want, got)
	}
	if want, got := "user", cfg.Username; want != got {
		t.Fatalf("expected Username = %q, got %q", want, got)
	}
	if want, got := "pwd", cfg.Password; want != got {
		t.Fatalf("expected Password = %q, got %q", want, got)
	}
	if want, got := 5, cfg.Shards; want != got {
		t.Fatalf("expected Shards = %v, got %v", want, got)
	}
	if want, got := 2, cfg.Replicas; want != got {
		t.Fatalf("expected Replicas = %v, got %v", want, got)
	}
	if want, got := true, *cfg.Sniff; want != got {
		t.Fatalf("expected Sniff = %v, got %v", want, got)
	}
	if want, got := false, *cfg.Healthcheck; want != got {
		t.Fatalf("expected Healthcheck = %v, got %v", want, got)
	}
	if want, got := "elastic.error.log", cfg.Errorlog; want != got {
		t.Fatalf("expected Errorlog = %q, got %q", want, got)
	}
	if want, got := "elastic.info.log", cfg.Infolog; want != got {
		t.Fatalf("expected Infolog = %q, got %q", want, got)
	}
	if want, got := "elastic.trace.log", cfg.Tracelog; want != got {
		t.Fatalf("expected Tracelog = %q, got %q", want, got)
	}
}

func TestParseDoesNotFailWithoutIndexName(t *testing.T) {
	urls := "http://user:pwd@elastic:19220/?shards=5&replicas=2&sniff=true&errorlog=elastic.error.log&infolog=elastic.info.log&tracelog=elastic.trace.log"
	cfg, err := Parse(urls)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := "http://elastic:19220", cfg.URL; want != got {
		t.Fatalf("expected URL = %q, got %q", want, got)
	}
	if want, got := "", cfg.Index; want != got {
		t.Fatalf("expected Index = %q, got %q", want, got)
	}
}

func TestParseTrimsIndexName(t *testing.T) {
	urls := "http://user:pwd@elastic:19220/store-blobs/?sniff=true"
	cfg, err := Parse(urls)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := "http://elastic:19220", cfg.URL; want != got {
		t.Fatalf("expected URL = %q, got %q", want, got)
	}
	if want, got := "store-blobs", cfg.Index; want != got {
		t.Fatalf("expected Index = %q, got %q", want, got)
	}
}

func TestParseTLSConfig(t *testing.T) {
	urls := "https://admin:secret@localhost:9200/logs?cacert=/etc/certs/ca.pem&clientcert=/etc/certs/client.pem&clientkey=/etc/certs/client-key.pem"
	cfg, err := Parse(urls)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := "https://localhost:9200", cfg.URL; want != got {
		t.Fatalf("expected URL = %q, got %q", want, got)
	}
	if want, got := "/etc/certs/ca.pem", cfg.CACert; want != got {
		t.Fatalf("expected CACert = %q, got %q", want, got)
	}
	if want, got := "/etc/certs/client.pem", cfg.ClientCert; want != got {
		t.Fatalf("expected ClientCert = %q, got %q", want, got)
	}
	if want, got := "/etc/certs/client-key.pem", cfg.ClientKey; want != got {
		t.Fatalf("expected ClientKey = %q, got %q", want, got)
	}
	if cfg.TLSSkipVerify {
		t.Fatal("expected TLSSkipVerify = false by default")
	}
}

func TestParseTLSSkipVerify(t *testing.T) {
	urls := "https://localhost:9200?tlsskipverify=true"
	cfg, err := Parse(urls)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLSSkipVerify {
		t.Fatal("expected TLSSkipVerify = true")
	}
}

func TestParseTLSConfigDefaults(t *testing.T) {
	// Without TLS params, fields should be empty/default
	urls := "http://localhost:9200/index"
	cfg, err := Parse(urls)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CACert != "" {
		t.Fatalf("expected empty CACert, got %q", cfg.CACert)
	}
	if cfg.ClientCert != "" {
		t.Fatalf("expected empty ClientCert, got %q", cfg.ClientCert)
	}
	if cfg.ClientKey != "" {
		t.Fatalf("expected empty ClientKey, got %q", cfg.ClientKey)
	}
	if cfg.TLSSkipVerify {
		t.Fatal("expected TLSSkipVerify = false by default")
	}
}
