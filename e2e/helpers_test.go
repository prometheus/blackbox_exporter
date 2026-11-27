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
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const composeFile = "compose.yaml"

func compose(args ...string) (string, error) {
	return composeContext(context.Background(), args...)
}

// composeContext stops the command when ctx is canceled, so an interrupt does not leave a build running.
func composeContext(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", composeFile}, args...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// docker runs a docker command and fails the test if it fails. It returns the output.
func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "docker", args...).CombinedOutput()
	require.NoError(t, err, "docker %s\n%s", strings.Join(args, " "), out)
	return string(out)
}

// startExporter runs an exporter container and returns its address on the host.
// The container gets the compose project label, so cleanup can find and remove it.
func startExporter(t *testing.T, name string, dockerArgs []string, args ...string) string {
	t.Helper()
	container := project + "-" + name

	require.False(t, closing.Load(), "e2e is shutting down")
	run := []string{
		"run", "-d", "--name", container, "--cap-add", "NET_RAW",
		"--label", projectLabel(), "--label", "com.docker.compose.service=" + name,
		"--network", project + "_default", "-p", "127.0.0.1::9115",
		"-v", runDir + "/config:/config", "-v", runDir + "/certs:/certs:ro",
	}
	run = append(append(append(run, dockerArgs...), image), args...)
	docker(t, run...)
	if closing.Load() {
		exec.Command("docker", "rm", "-f", container).Run()
		t.Fatal("e2e is shutting down")
	}
	// Like the compose blackbox service, so the exporter can resolve testserver-v4.
	docker(t, "network", "connect", project+"_v4only", container)

	// Plain exec.Command, because t.Context is canceled before cleanups run.
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail=50", container).CombinedOutput()
			t.Logf("%s logs:\n%s", container, logs)
		}
		if os.Getenv("E2E_KEEP") == "" {
			exec.Command("docker", "rm", "-f", container).Run()
		}
	})

	addr, _, _ := strings.Cut(docker(t, "port", container, "9115"), "\n")
	return strings.TrimSpace(addr)
}

// waitStatus polls, because a new exporter takes a moment to listen.
func waitStatus(t *testing.T, c *http.Client, u string, want int) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		code, _, err := get(c, u)
		require.NoError(ct, err)
		require.Equal(ct, want, code)
	}, 30*time.Second, 500*time.Millisecond, "GET %s", u)
}

func get(c *http.Client, u string) (int, string, error) {
	resp, err := c.Get(u)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}

func mustGet(t *testing.T, u string) string {
	t.Helper()
	code, body, err := get(httpClient, u)
	require.NoError(t, err, "GET %s", u)
	require.Equal(t, http.StatusOK, code, "GET %s\n%s", u, body)
	return body
}
