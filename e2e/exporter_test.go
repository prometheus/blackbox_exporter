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

//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImageDefaults uses the image's own CMD and baked-in config.
func TestImageDefaults(t *testing.T) {
	base := "http://" + startExporter(t, "defaults", nil)
	waitStatus(t, httpClient, base+"/-/healthy", http.StatusOK)
	// Only the baked config has tcp_connect.
	wantSuccess(t, base, "tcp_connect", "testserver:30080", 1)
}

func TestReload(t *testing.T) {
	path := filepath.Join(runDir, "config", "blackbox.yml")
	orig, err := os.ReadFile(path)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, os.WriteFile(path, orig, 0o644), "restore config")
		code, body := post(t, exporterURL+"/-/reload")
		require.Equal(t, http.StatusOK, code, "reload of the restored config: %s", body)
	})

	t.Run("endpoint", func(t *testing.T) {
		writeConfig(t, path, "reloaded")
		code, body := post(t, exporterURL+"/-/reload")
		require.Equal(t, http.StatusOK, code, "reload of a valid config: %s", body)
		wantSuccess(t, exporterURL, "http_reloaded", "http://testserver:30080", 1)

		require.NoError(t, os.WriteFile(path, []byte("modules:\n  broken:\n    prober: nope\n"), 0o644))
		code, _ = post(t, exporterURL+"/-/reload")
		require.Equal(t, http.StatusInternalServerError, code, "reload of a broken config")
		wantSuccess(t, exporterURL, "http_reloaded", "http://testserver:30080", 1)
		require.Contains(t, mustGet(t, exporterURL+"/metrics"), "blackbox_exporter_config_last_reload_successful 0")
	})

	// SIGHUP kills a process that has no handler for it. A separate exporter keeps that from taking down the shared one.
	t.Run("sighup", func(t *testing.T) {
		hupPath := filepath.Join(runDir, "config", "sighup.yml")
		writeConfig(t, hupPath)
		base := "http://" + startExporter(t, "sighup", nil, "--config.file=/config/sighup.yml")
		waitStatus(t, httpClient, base+"/-/healthy", http.StatusOK)
		writeConfig(t, hupPath, "after sighup")
		docker(t, "kill", "-s", "HUP", project+"-sighup")
		waitModule(t, base, "http_after_sighup")
	})

	t.Run("auto reload", func(t *testing.T) {
		autoPath := filepath.Join(runDir, "config", "auto.yml")
		writeConfig(t, autoPath)
		base := "http://" + startExporter(t, "autoreload", nil,
			"--config.file=/config/auto.yml", "--config.enable-auto-reload", "--config.auto-reload-interval=1")
		waitStatus(t, httpClient, base+"/-/healthy", http.StatusOK)
		writeConfig(t, autoPath, "auto reloaded")
		waitModule(t, base, "http_auto_reloaded")
	})
}

func TestLogs(t *testing.T) {
	t.Run("by target", func(t *testing.T) {
		target := "http://testserver:30080/?logs-by-target"
		probe(t, "http_2xx", target)
		body := mustGet(t, exporterURL+"/logs?"+url.Values{"target": {target}}.Encode())
		require.Contains(t, body, "Beginning probe")
	})

	t.Run("by id with history limit", func(t *testing.T) {
		base := "http://" + startExporter(t, "history", nil, "--config.file=/config/blackbox.yml", "--history.limit=1", "--log.prober=debug")
		waitStatus(t, httpClient, base+"/-/healthy", http.StatusOK)
		first, second := "http://testserver:30080/?first", "http://testserver:30080/?second"
		probeAt(t, base, "http_2xx", first)
		probeAt(t, base, "http_2xx", second)

		code, _, err := get(httpClient, base+"/logs?"+url.Values{"target": {first}}.Encode())
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, code, "/logs for a probe past --history.limit")
		ids := regexp.MustCompile(`logs\?id=(\d+)`).FindAllStringSubmatch(mustGet(t, base+"/"), -1)
		require.Len(t, ids, 1, "probes on the landing page")
		require.Contains(t, mustGet(t, base+"/logs?id="+ids[0][1]), second, "/logs?id= is not the last probe")
	})
}

func TestWebConfig(t *testing.T) {
	authURL := "https://" + startExporter(t, "webconfig", nil, "--config.file=/config/blackbox.yml", "--web.config.file=/config/web-config.yml")
	cert, err := os.ReadFile(filepath.Join(runDir, "certs", "server.crt"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(cert), "no cert in server.crt")
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	waitStatus(t, c, authURL+"/-/healthy", http.StatusUnauthorized)

	for _, p := range []string{"/-/healthy", "/metrics", "/probe?" + url.Values{"module": {"http_2xx"}, "target": {"http://testserver:30080"}}.Encode()} {
		code, _, err := get(c, authURL+p)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, code, "%s without credentials", p)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL+p, nil)
		require.NoError(t, err)
		req.SetBasicAuth("e2e", "e2e-password")
		resp, err := c.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s with credentials", p)
	}
}

func TestRoutePrefix(t *testing.T) {
	noRedirect := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for name, flag := range map[string]string{
		"external url": "--web.external-url=http://localhost:9115/bbe/",
		"route prefix": "--web.route-prefix=/bbe",
	} {
		t.Run(name, func(t *testing.T) {
			base := "http://" + startExporter(t, strings.ReplaceAll(name, " ", "-"), nil, "--config.file=/config/blackbox.yml", flag)
			waitStatus(t, httpClient, base+"/bbe/-/healthy", http.StatusOK)
			wantSuccess(t, base+"/bbe", "http_2xx", "http://testserver:30080", 1)

			code, _, err := get(noRedirect, base+"/-/healthy")
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, code, "/-/healthy without the prefix")
			code, _, err = get(noRedirect, base+"/")
			require.NoError(t, err)
			require.Equal(t, http.StatusFound, code, "/ without the prefix")
		})
	}
}

// writeConfig writes a config with http_2xx and one http module per name.
// The reload tests use the module names to see which version of the config an exporter has loaded.
func writeConfig(t *testing.T, path string, names ...string) {
	t.Helper()
	var cases []probeCase
	for _, n := range names {
		cases = append(cases, probeCase{prober: "http", name: n})
	}
	cfg, err := moduleConfig(cases)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, cfg, 0o644))
}

// waitModule polls until the exporter has loaded the module, because SIGHUP and auto reload are asynchronous.
func waitModule(t *testing.T, base, module string) {
	t.Helper()
	q := url.Values{"module": {module}, "target": {"http://testserver:30080"}}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		code, body, err := get(httpClient, base+"/probe?"+q.Encode())
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, code)
		require.Contains(ct, body, "probe_success 1")
	}, 30*time.Second, 500*time.Millisecond, "module %s never loaded", module)
}

// post sends an empty POST, for /-/reload.
func post(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := httpClient.Post(u, "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
