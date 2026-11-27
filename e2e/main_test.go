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

// Package e2e tests the exporter's Docker image. See README.md.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Set by setup() and read by the tests.
var (
	// project names the compose project and prefixes every container. Unique per run, so parallel runs do not collide.
	project string
	// image is the exporter image that compose builds.
	image string
	// runDir holds this run's config, certificates and the testserver binary.
	runDir string
	// exporterURL is the compose blackbox service, with the config in runDir/config/blackbox.yml.
	exporterURL string

	httpClient  = &http.Client{Timeout: 30 * time.Second}
	cleanupOnce sync.Once
	// closing stops startExporter from adding containers while cleanup runs.
	closing atomic.Bool

	// setupCtx lets cleanup stop a running build.
	setupCtx, cancelSetup = context.WithCancel(context.Background())
)

// webConfig is for TestWebConfig: TLS with the generated certificate and basic auth for the user e2e.
// The file keeps only a bcrypt hash, so the hash below is of the password e2e-password, which the test sends.
const webConfig = `
tls_server_config:
  cert_file: /certs/server.crt
  key_file: /certs/server.key
basic_auth_users:
  e2e: $2b$10$kimYjAhxinmKBC6LBqom7edXSuODxDVVaUvfccJ6iKAdK6ziEIg/a
`

func TestMain(m *testing.M) {
	flag.Parse()
	go cleanupOnInterrupt()

	code := 1
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
	} else {
		code = m.Run()
	}
	if code != 0 {
		printComposeLogs()
	}
	cleanup()
	os.Exit(code)
}

// cleanupOnInterrupt cleans up on Ctrl-C, SIGTERM or shortly before the go test timeout.
// go test panics at the timeout without running any cleanup, so waiting for it would leak the containers.
func cleanupOnInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	var nearTimeout <-chan time.Time // nil blocks forever, so no timeout means no timer.
	if d := flag.Lookup("test.timeout").Value.(flag.Getter).Get().(time.Duration); d > 0 {
		// Leaves 30s for cleanup, or a quarter of a short timeout.
		nearTimeout = time.After(d - min(30*time.Second, d/4))
	}

	select {
	case <-sig:
		fmt.Fprintln(os.Stderr, "e2e: interrupted")
	case <-nearTimeout:
		fmt.Fprintln(os.Stderr, "e2e: test timeout is near")
	}
	printComposeLogs()
	cleanup()
	os.Exit(1)
}

func printComposeLogs() {
	if out, _ := compose("logs", "--no-color", "--tail=50"); out != "" {
		fmt.Fprintln(os.Stderr, out)
	}
}

// cleanup removes everything the run created. It runs once, from the end of TestMain or from cleanupOnInterrupt.
func cleanup() {
	cleanupOnce.Do(func() {
		closing.Store(true)
		cancelSetup()
		if os.Getenv("E2E_KEEP") != "" {
			fmt.Fprintf(os.Stderr, "e2e: kept %s. Remove it with: docker rm -f $(docker ps -aq --filter label=%s); docker network rm %s_default %s_v4only; docker rmi %s; rm -rf %s\n",
				runDir, projectLabel(), project, project, image, runDir)
			return
		}
		if project != "" {
			// Twice, because a test that was past the closing check can start a container during the first pass.
			for range 2 {
				// compose down skips containers from startExporter, even with the project label.
				if ids, _ := exec.Command("docker", "ps", "-aq", "--filter", "label="+projectLabel()).Output(); len(ids) > 0 {
					exec.Command("docker", append([]string{"rm", "-f"}, strings.Fields(string(ids))...)...).Run()
				}
				compose("down", "-v", "--rmi", "local")
			}
			// compose keeps an image that has an explicit name, so remove it here.
			exec.Command("docker", "rmi", image).Run()
		}
		if runDir != "" {
			os.RemoveAll(runDir)
		}
	})
}

func projectLabel() string { return "com.docker.compose.project=" + project }

// setup builds the binaries, writes the files the containers mount and starts the compose services.
func setup() error {
	var err error
	if runDir, err = os.MkdirTemp("", "bbe-e2e-"); err != nil {
		return err
	}
	project = filepath.Base(runDir)
	image = project + "-blackbox"

	// Build for the daemon's arch, which can differ from the host Go toolchain's.
	out, err := exec.CommandContext(setupCtx, "docker", "version", "-f", "{{.Server.Arch}}").Output()
	if err != nil {
		return fmt.Errorf("docker version: %w", err)
	}
	arch, err := imageArch(strings.TrimSpace(string(out)))
	if err != nil {
		return err
	}
	// compose.yaml reads these.
	os.Setenv("COMPOSE_PROJECT_NAME", project)
	os.Setenv("E2E_RUN_DIR", runDir)
	os.Setenv("E2E_ARCH", arch)

	if err := writeMountedFiles(); err != nil {
		return err
	}
	// The binary and the image build share .build/, so two runs must not overlap here.
	unlock, err := lockBuild()
	if err != nil {
		return err
	}
	defer unlock()
	if err := buildBinaries(arch); err != nil {
		return err
	}
	if out, err := composeContext(setupCtx, "up", "-d", "--build", "--wait", "--quiet-pull"); err != nil {
		return fmt.Errorf("compose up: %w\n%s", err, out)
	}
	exporterURL, err = hostURL("blackbox", "9115")
	return err
}

// imageArch maps the daemon's arch name to the one the repo uses for images and .build/ directories.
// Makefile.common calls 32-bit ARM armv7. The Dockerfile has no image for other arches.
func imageArch(daemonArch string) (string, error) {
	switch daemonArch {
	case "amd64", "arm64", "ppc64le", "riscv64", "s390x":
		return daemonArch, nil
	case "arm":
		return "armv7", nil
	}
	return "", fmt.Errorf("unsupported docker arch %q", daemonArch)
}

// lockBuild holds an exclusive lock on a file in .build/ until the returned function runs.
func lockBuild() (func(), error) {
	if err := os.MkdirAll(filepath.Join("..", ".build"), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join("..", ".build", "e2e.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// writeMountedFiles writes what the containers mount: the base config, the web config and the certificates.
func writeMountedFiles() error {
	configDir, certDir := filepath.Join(runDir, "config"), filepath.Join(runDir, "certs")
	for _, d := range []string{configDir, certDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// Only http_2xx, because each test writes the modules it needs.
	cfg, err := moduleConfig(nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(configDir, "blackbox.yml"), cfg, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(configDir, "web-config.yml"), []byte(webConfig), 0o644); err != nil {
		return err
	}
	return writeCerts(certDir)
}

func buildBinaries(arch string) error {
	// The repo Dockerfile copies the exporter from .build/, which Git ignores. This overwrites your own build for this arch.
	if err := goBuild(filepath.Join("..", ".build", "linux-"+arch, "blackbox_exporter"), "..", arch); err != nil {
		return err
	}
	return goBuild(filepath.Join(runDir, "testserver"), "./testserver", arch)
}

func goBuild(out, pkg, arch string) error {
	// Same toolchain as the test, which make test-e2e sets.
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	goarch, goarm := arch, ""
	if arch == "armv7" {
		goarch, goarm = "arm", "7"
	}
	cmd := exec.CommandContext(setupCtx, goTool, "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "GOARM="+goarm, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
	}
	return nil
}

func hostURL(service, port string) (string, error) {
	out, err := compose("port", service, port)
	if err != nil {
		return "", fmt.Errorf("compose port %s: %w\n%s", service, err, out)
	}
	return "http://" + strings.TrimSpace(out), nil
}

func writeCerts(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "blackbox"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", der); err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, "server.key"), "PRIVATE KEY", keyDER)
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644)
}
