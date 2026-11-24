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

//go:build !windows

package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestGracefulShutdownDrainsProbes checks that a probe that is in flight when
// the exporter receives SIGTERM still completes before the process exits.
func TestGracefulShutdownDrainsProbes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the exporter binary")
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	releaseTarget := func() { releaseOnce.Do(func() { close(release) }) }
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(target.Close)
	t.Cleanup(releaseTarget)

	dir := t.TempDir()
	bin := filepath.Join(dir, "blackbox_exporter")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "blackbox.yml")
	if err := os.WriteFile(cfg, []byte("modules:\n  http_2xx:\n    prober: http\n    timeout: 10s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "--config.file="+cfg, "--web.listen-address=127.0.0.1:0")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	// Forward log lines so the test can wait for events instead of sleeping.
	var (
		mu     sync.Mutex
		output strings.Builder
	)
	lines := make(chan string, 100)
	go func() {
		defer close(lines)
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			mu.Lock()
			output.WriteString(s.Text() + "\n")
			mu.Unlock()
			lines <- s.Text()
		}
	}()
	logs := func() string {
		mu.Lock()
		defer mu.Unlock()
		return output.String()
	}
	waitForLog := func(re *regexp.Regexp) []string {
		t.Helper()
		timeout := time.After(10 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("exporter exited before logging %q\n%s", re, logs())
				}
				if m := re.FindStringSubmatch(l); m != nil {
					return m
				}
			case <-timeout:
				t.Fatalf("timed out waiting for log %q\n%s", re, logs())
			}
		}
	}

	addr := waitForLog(regexp.MustCompile(`msg="Listening on" address=(\S+)`))[1]

	type result struct {
		body string
		err  error
	}
	probe := make(chan result, 1)
	go func() {
		u := "http://" + addr + "/probe?module=http_2xx&target=" + url.QueryEscape(target.URL)
		resp, err := http.Get(u)
		if err != nil {
			probe <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		probe <- result{body: string(b), err: err}
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("probe did not reach the target\n%s", logs())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitForLog(regexp.MustCompile(`Received SIGTERM`))
	releaseTarget()

	select {
	case r := <-probe:
		if r.err != nil {
			t.Fatalf("in-flight probe failed during shutdown: %v\n%s", r.err, logs())
		}
		if !strings.Contains(r.body, "probe_success 1") {
			t.Fatalf("in-flight probe did not succeed during shutdown:\n%s\n%s", r.body, logs())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("in-flight probe did not finish\n%s", logs())
	}

	// Read the remaining log lines before cmd.Wait, which closes the pipe.
	done := make(chan error, 1)
	go func() {
		for range lines {
		}
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exporter did not exit cleanly on SIGTERM: %v\n%s", err, logs())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("exporter did not exit within 10s of SIGTERM\n%s", logs())
	}
}
