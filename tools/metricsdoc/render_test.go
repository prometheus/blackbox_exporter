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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	out := string(render(&catalog{
		Probers: []string{"b", "a"},
		Metrics: []*metric{
			{Name: "demo_unknown_total", Type: "counter", Help: "Unknown | <modules>.", Exporter: true},
			{Name: "probe_expect_info", Type: "gauge", Help: "Matched.", LabelsFrom: "query_response[].labels", Probers: []string{"b"}},
			{Name: "probe_shared", Type: "gauge", Help: "Shared.", Labels: []string{"x", "y"}, Probers: []string{"b", "a"}},
			{Name: "probe_success", Type: "gauge", Help: "Success.", EveryProbe: true},
		},
	}))
	for _, want := range []string{
		"## Exporter metrics\n\nServed on `/metrics`.\n\n| Metric | Type | Labels | Help |\n|---|---|---|---|\n| `demo_unknown_total` | counter |  | Unknown \\| &lt;modules&gt;. |\n",
		"| `probe_success` | gauge |  | Success. |\n",
		"| Metric | b | a |\n|---|:-:|:-:|\n| `probe_expect_info` | ✓ | |\n| `probe_shared` | ✓ | ✓ |\n",
		"### b\n\n| Metric | Type | Labels | Help |\n|---|---|---|---|\n| `probe_expect_info` | gauge | names set by `query_response[].labels` | Matched. |\n| `probe_shared` | gauge | `x`, `y` | Shared. |\n",
		"### a\n\n| Metric | Type | Labels | Help |\n|---|---|---|---|\n| `probe_shared` | gauge | `x`, `y` | Shared. |\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output does not contain\n%s\ngot:\n%s", want, out)
		}
	}
	if strings.Count(out, "probe_success") != 1 {
		t.Errorf("metrics returned by every probe should only be listed once, got:\n%s", out)
	}
}

func TestSplice(t *testing.T) {
	const generated = "## Generated\n"
	for _, tc := range []struct {
		name    string
		doc     string
		want    string
		wantErr string
	}{
		{
			name: "replaces between markers only",
			doc:  "# Title\n\nIntro.\n\n" + beginMarker + "\nold\ntable\n" + endMarker + "\n\n## Notes\n",
			want: "# Title\n\nIntro.\n\n" + beginMarker + "\n\n## Generated\n\n" + endMarker + "\n\n## Notes\n",
		},
		{
			name: "empty block",
			doc:  beginMarker + endMarker,
			want: beginMarker + "\n\n## Generated\n\n" + endMarker,
		},
		{
			name:    "missing begin marker",
			doc:     "# Title\n" + endMarker + "\n",
			wantErr: "want exactly one " + beginMarker + " line, found 0",
		},
		{
			name:    "missing end marker",
			doc:     beginMarker + "\n",
			wantErr: "want exactly one " + endMarker + " line, found 0",
		},
		{
			name:    "duplicate begin marker",
			doc:     beginMarker + "\n" + beginMarker + "\n" + endMarker + "\n",
			wantErr: "want exactly one " + beginMarker + " line, found 2",
		},
		{
			name:    "markers in the wrong order",
			doc:     endMarker + "\n" + beginMarker + "\n",
			wantErr: "the end marker comes before the begin marker",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splice([]byte(tc.doc), []byte(generated))
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("got error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, tc.want)
			}
			again, err := splice(got, []byte(generated))
			if err != nil || string(again) != string(got) {
				t.Fatalf("splice is not idempotent, second run got:\n%q", again)
			}
		})
	}
}

// TestGenerateCRLF checks that a doc with CRLF line endings, as in a Windows
// checkout, is up to date when its LF version is.
func TestGenerateCRLF(t *testing.T) {
	root := writeTree(t, map[string]string{
		"prober/handler.go": "package prober\n\nvar Probers = map[string]ProbeFn{}\n",
		"Metrics.md":        "# Metrics\n\n" + beginMarker + "\n" + endMarker + "\n\nNotes.\n",
	})
	doc := filepath.Join(root, "Metrics.md")
	_, want, err := generate(root, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(doc, bytes.ReplaceAll(want, []byte("\n"), []byte("\r\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	current, updated, err := generate(root, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, updated) || !bytes.Equal(updated, want) {
		t.Errorf("CRLF doc is reported as out of date:\ncurrent %q\nupdated %q\nwant    %q", current, updated, want)
	}
}
