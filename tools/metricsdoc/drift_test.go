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
	"testing"
)

// TestMetricsDocUpToDate fails when Metrics.md does not match the metric
// definitions in the source code.
func TestMetricsDocUpToDate(t *testing.T) {
	current, updated, err := generate("../..", "../../Metrics.md")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, updated) {
		return
	}
	cur, upd := bytes.Split(current, []byte("\n")), bytes.Split(updated, []byte("\n"))
	line := 0
	for line < min(len(cur), len(upd)) && bytes.Equal(cur[line], upd[line]) {
		line++
	}
	var have, want []byte
	if line < len(cur) {
		have = cur[line]
	}
	if line < len(upd) {
		want = upd[line]
	}
	t.Fatalf("Metrics.md is out of date; run `make metrics-docs`.\nFirst difference at line %d:\nhave: %s\nwant: %s", line+1, have, want)
}
