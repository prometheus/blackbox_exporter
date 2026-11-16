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
	"syscall"
	"testing"
	"time"
)

var (
	// Unique per run, so parallel runs do not collide.
	project string

	image       string
	exporterURL string
	runDir      string
	httpClient  = &http.Client{Timeout: 30 * time.Second}
	cleanupOnce sync.Once
)

// The bcrypt hash is of e2e-password.
const webConfig = `
tls_server_config:
  cert_file: /certs/server.crt
  key_file: /certs/server.key
basic_auth_users:
  e2e: $2b$10$kimYjAhxinmKBC6LBqom7edXSuODxDVVaUvfccJ6iKAdK6ziEIg/a
`

func TestMain(m *testing.M) {
	flag.Parse()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		exit("interrupted", 1)
	}()
	// A go test timeout panics without running deferred code, so run the cleanup 30s before it.
	if d := flag.Lookup("test.timeout").Value.(flag.Getter).Get().(time.Duration); d > time.Minute {
		time.AfterFunc(d-30*time.Second, func() { exit("test timeout is near", 1) })
	}

	if err := setup(); err != nil {
		exit(err.Error(), 1)
	}
	code := m.Run()
	if code != 0 {
		exit("tests failed", code)
	}
	exit("", 0)
}

func exit(msg string, code int) {
	cleanupOnce.Do(func() {
		if msg != "" {
			fmt.Fprintln(os.Stderr, "e2e:", msg)
			if out, _ := compose("logs", "--no-color", "--tail=50"); out != "" {
				fmt.Fprintln(os.Stderr, out)
			}
		}
		if os.Getenv("E2E_KEEP") != "" {
			fmt.Fprintf(os.Stderr, "e2e: kept %s. Remove it with: docker rm -f $(docker ps -aq --filter label=%s); docker compose -p %s down -v && docker rmi %s && rm -rf %s\n",
				runDir, projectLabel(), project, image, runDir)
			return
		}
		if project != "" {
			// compose down skips containers from startExporter, even with the project label.
			if ids, _ := exec.Command("docker", "ps", "-aq", "--filter", "label="+projectLabel()).Output(); len(ids) > 0 {
				exec.Command("docker", append([]string{"rm", "-f"}, strings.Fields(string(ids))...)...).Run()
			}
			compose("down", "-v", "--rmi", "local")
		}
		if runDir != "" {
			os.RemoveAll(runDir)
		}
	})
	os.Exit(code)
}

func projectLabel() string { return "com.docker.compose.project=" + project }

func setup() error {
	var err error
	if runDir, err = os.MkdirTemp("", "bbe-e2e-"); err != nil {
		return err
	}
	project = filepath.Base(runDir)
	image = project + "-blackbox"

	// Build for the daemon's arch, which can differ from the host Go toolchain's.
	out, err := exec.Command("docker", "version", "-f", "{{.Server.Arch}}").Output()
	if err != nil {
		return fmt.Errorf("docker version: %w", err)
	}
	arch := strings.TrimSpace(string(out))
	os.Setenv("COMPOSE_PROJECT_NAME", project)
	os.Setenv("E2E_RUN_DIR", runDir)
	os.Setenv("E2E_ARCH", arch)

	binDir := filepath.Join(runDir, "image", ".build", "linux-"+arch)
	for _, d := range []string{filepath.Join(runDir, "config"), filepath.Join(runDir, "certs"), binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	cfg, err := moduleConfig(probeCases)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, "config", "blackbox.yml"), cfg, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, "config", "web-config.yml"), []byte(webConfig), 0o644); err != nil {
		return err
	}
	if err := writeCerts(filepath.Join(runDir, "certs")); err != nil {
		return err
	}
	for _, f := range []string{"Dockerfile", "blackbox.yml"} {
		if err := copyFile(filepath.Join("..", f), filepath.Join(runDir, "image", f)); err != nil {
			return err
		}
	}
	if err := goBuild(filepath.Join(binDir, "blackbox_exporter"), "..", arch); err != nil {
		return err
	}
	if err := goBuild(filepath.Join(runDir, "badserver"), "./badserver", arch); err != nil {
		return err
	}

	if out, err := compose("up", "-d", "--build", "--wait", "--quiet-pull"); err != nil {
		return fmt.Errorf("compose up: %w\n%s", err, out)
	}
	exporterURL, err = hostURL("blackbox", "9115")
	return err
}

func goBuild(out, pkg, arch string) error {
	// Same toolchain as the test, which make test-e2e sets.
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	cmd := exec.Command(goTool, "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
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

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
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
