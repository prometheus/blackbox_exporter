// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	dto "github.com/prometheus/client_model/go"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
)

// TestCatalogCoversRuntimeMetrics runs the probers against local servers and
// checks that every metric they return is in the catalog with the same type,
// help and label names, and is attributed to the prober that returned it.
//
// The servers and modules are set up so that the probes also return the
// metrics that only appear under some conditions, such as TLS, check_revoked
// or query_response labels. The test checks that they do, so that a change in
// the setup cannot silently make the check weaker.
func TestCatalogCoversRuntimeMetrics(t *testing.T) {
	c, err := extract("../..")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*metric{}
	for _, m := range c.Metrics {
		byName[m.Name] = m
	}

	targets := map[string]func(*testing.T) (string, config.Module){
		"http":      httpTarget,
		"tcp":       tcpTarget,
		"dns":       dnsTarget,
		"grpc":      grpcTarget,
		"unix":      unixTarget,
		"websocket": websocketTarget,
	}
	// Metrics that each probe must return, in addition to being in the catalog.
	mustReturn := map[string][]string{
		"http": {
			"probe_failed_due_to_cel", "probe_http_last_modified_timestamp_seconds", "probe_ip_protocol",
			"probe_ssl_crl_fetch_time_seconds", "probe_ssl_last_chain_expiry_timestamp_seconds", "probe_tls_cipher_info",
		},
		"tcp":       {"probe_expect_info", "probe_ip_protocol", "probe_ssl_crl_fetch_time_seconds", "probe_tls_cipher_info"},
		"dns":       {"probe_dns_serial", "probe_ip_protocol"},
		"grpc":      {"probe_grpc_healthcheck_response", "probe_ssl_crl_fetch_time_seconds", "probe_tls_version_info"},
		"unix":      {"probe_failed_due_to_regex"},
		"websocket": {"probe_ip_protocol", "probe_websocket_connection_upgraded"},
		"handler":   {"probe_duration_seconds", "probe_success", "probe_timeout_seconds"},
		"exporter":  {"blackbox_exporter_build_info", "blackbox_exporter_config_last_reload_successful"},
	}
	for _, name := range c.Probers {
		t.Run(name, func(t *testing.T) {
			if name == "icmp" {
				t.Skip("the icmp prober needs raw sockets")
			}
			newTarget, ok := targets[name]
			if !ok {
				t.Fatalf("no runtime check for prober %q, add one to this test", name)
			}
			target, module := newTarget(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			reg := prometheus.NewRegistry()
			if !prober.Probers[name](ctx, target, module, reg, promslog.NewNopLogger()) {
				t.Fatalf("probe of %s failed", target)
			}
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatal(err)
			}
			checkFamilies(t, byName, mfs, mustReturn[name], func(m *metric) bool { return slices.Contains(m.Probers, name) })
		})
	}

	t.Run("handler", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go serveOnce(ln, "")
		cfg := &config.Config{Modules: map[string]config.Module{"tcp_connect": {
			Prober:  "tcp",
			Timeout: 10 * time.Second,
			TCP:     config.TCPProbe{IPProtocol: "ip4", IPProtocolFallback: true},
		}}}
		req := httptest.NewRequest(http.MethodGet, "/probe?module=tcp_connect&target="+url.QueryEscape(ln.Addr().String()), nil)
		rec := httptest.NewRecorder()
		prober.Handler(rec, req, cfg, promslog.NewNopLogger(), &prober.ResultHistory{}, 0.5, nil, nil, &promslog.Config{Writer: io.Discard})
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d: %s", rec.Code, rec.Body)
		}
		parser := expfmt.NewTextParser(model.UTF8Validation)
		families, err := parser.TextToMetricFamilies(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		var mfs []*dto.MetricFamily
		for _, mf := range families {
			mfs = append(mfs, mf)
		}
		checkFamilies(t, byName, mfs, mustReturn["handler"], func(m *metric) bool { return m.EveryProbe || slices.Contains(m.Probers, "tcp") })
	})

	// The exporter metrics of package main cannot be created from here.
	t.Run("exporter", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		config.NewSafeConfig(reg)
		reg.MustRegister(versioncollector.NewCollector("blackbox_exporter"))
		mfs, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		checkFamilies(t, byName, mfs, mustReturn["exporter"], func(m *metric) bool { return m.Exporter })
	})
}

func checkFamilies(t *testing.T, byName map[string]*metric, mfs []*dto.MetricFamily, mustReturn []string, inScope func(*metric) bool) {
	t.Helper()
	returned := map[string]bool{}
	for _, mf := range mfs {
		returned[mf.GetName()] = true
	}
	for _, name := range mustReturn {
		if !returned[name] {
			t.Errorf("%s was not returned, check the test setup", name)
		}
	}
	for _, mf := range mfs {
		name := mf.GetName()
		m := byName[name]
		if m == nil {
			t.Errorf("%s is missing from the catalog", name)
			continue
		}
		if !inScope(m) {
			t.Errorf("%s is returned here, but the catalog has it for probers %v (exporter %t, every probe %t)", name, m.Probers, m.Exporter, m.EveryProbe)
		}
		if got := strings.ToLower(mf.GetType().String()); got != m.Type {
			t.Errorf("%s: got type %s, catalog has %s", name, got, m.Type)
		}
		if mf.GetHelp() != m.Help {
			t.Errorf("%s: got help %q, catalog has %q", name, mf.GetHelp(), m.Help)
		}
		if m.LabelsFrom != "" {
			continue
		}
		want := slices.Sorted(slices.Values(m.Labels))
		for _, s := range mf.GetMetric() {
			var got []string
			for _, l := range s.GetLabel() {
				got = append(got, l.GetName())
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s: got labels %v, catalog has %v", name, got, want)
			}
		}
	}
}

// serveOnce accepts one connection, writes banner and closes the connection.
func serveOnce(ln net.Listener, banner string) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(banner))
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	ts.Close()
	return ts.TLS.Certificates[0]
}

func httpTarget(t *testing.T) (string, config.Module) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	t.Cleanup(ts.Close)
	cel := config.MustNewCELProgram("body.ok == false")
	return ts.URL, config.Module{Timeout: 10 * time.Second, HTTP: config.HTTPProbe{
		IPProtocol:               "ip4",
		IPProtocolFallback:       true,
		CheckRevoked:             true,
		FailIfBodyJSONMatchesCEL: &cel,
		HTTPClientConfig:         pconfig.HTTPClientConfig{TLSConfig: pconfig.TLSConfig{InsecureSkipVerify: true}},
	}}
}

func tcpTarget(t *testing.T) (string, config.Module) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveOnce(ln, "SSH-2.0-OpenSSH_9.6\r\n")
	return ln.Addr().String(), config.Module{Timeout: 10 * time.Second, TCP: config.TCPProbe{
		IPProtocol:         "ip4",
		IPProtocolFallback: true,
		TLS:                true,
		TLSConfig:          pconfig.TLSConfig{InsecureSkipVerify: true},
		CheckRevoked:       true,
		QueryResponse: []config.QueryResponse{{
			Expect: config.MustNewRegexp(`^SSH-2.0-(\S+)`),
			Labels: []config.Label{{Name: "software", Value: "${1}"}},
		}},
	}}
}

func dnsTarget(t *testing.T) (string, config.Module) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if soa, err := dns.NewRR("example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"); err == nil {
			m.Answer = append(m.Answer, soa)
		}
		_ = w.WriteMsg(m)
	})
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String(), config.Module{Timeout: 10 * time.Second, DNS: config.DNSProbe{
		IPProtocol:         "ip4",
		IPProtocolFallback: true,
		QueryName:          "example.com",
		QueryType:          "SOA",
	}}
}

func grpcTarget(t *testing.T) (string, config.Module) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{testCertificate(t)}})))
	grpc_health_v1.RegisterHealthServer(s, health.NewServer())
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(s.Stop)
	return ln.Addr().String(), config.Module{Timeout: 10 * time.Second, GRPC: config.GRPCProbe{
		PreferredIPProtocol: "ip4",
		IPProtocolFallback:  true,
		TLS:                 true,
		TLSConfig:           pconfig.TLSConfig{InsecureSkipVerify: true},
		CheckRevoked:        true,
	}}
}

func unixTarget(t *testing.T) (string, config.Module) {
	// A short directory, because macOS limits socket paths to 104 bytes.
	dir, err := os.MkdirTemp("", "bbe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveOnce(ln, "hello\n")
	return ln.Addr().String(), config.Module{Timeout: 10 * time.Second, Unix: config.UnixProbe{
		QueryResponse: []config.QueryResponse{{Expect: config.MustNewRegexp("^hello")}},
	}}
}

func websocketTarget(t *testing.T) (string, config.Module) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage() // Returns when the prober closes the connection.
	}))
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http"), config.Module{Timeout: 10 * time.Second, Websocket: config.WebsocketProbe{
		IPProtocol:         "ip4",
		IPProtocolFallback: true,
	}}
}
