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
	cmd := exec.Command("docker", append([]string{"compose", "-f", composeFile}, args...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// startExporter adds the compose project label, so exit can find and remove the container.
func startExporter(t *testing.T, name string, dockerArgs []string, args ...string) string {
	t.Helper()
	container := project + "-" + name
	run := []string{
		"run", "-d", "--name", container,
		"--label", projectLabel(), "--label", "com.docker.compose.service=" + name,
		"--network", project + "_default", "-p", "127.0.0.1::9115",
		"-v", runDir + "/config:/config", "-v", runDir + "/certs:/certs:ro",
	}
	run = append(append(append(run, dockerArgs...), image), args...)
	out, err := exec.CommandContext(t.Context(), "docker", run...).CombinedOutput()
	require.NoError(t, err, "docker run %s\n%s", name, out)
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
	out, err = exec.CommandContext(t.Context(), "docker", "port", container, "9115").Output()
	require.NoError(t, err, "docker port %s", container)
	addr, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(addr)
}

// waitStatus polls, because a new exporter takes a moment to listen.
func waitStatus(t *testing.T, c *http.Client, u string, want int) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		code, _, err := get(c, u)
		require.NoError(ct, err)
		assert.Equal(ct, want, code)
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
