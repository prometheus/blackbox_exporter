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

// Command metricsdoc regenerates the metric tables in Metrics.md from the
// metric definitions in the source code. It rewrites only the text between
// the generated-metrics markers.
//
// Usage:
//
//	go run ./tools/metricsdoc -root . -out Metrics.md
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "Repository root to read the metric definitions from.")
	out := flag.String("out", "Metrics.md", "Markdown file to update between the generated-metrics markers.")
	flag.Parse()

	current, updated, err := generate(*root, *out)
	if err == nil && !bytes.Equal(current, updated) {
		err = os.WriteFile(*out, updated, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "metricsdoc:", err)
		os.Exit(1)
	}
}

// generate returns the current content of the doc at docPath, with LF line
// endings, and the content it should have for the metric definitions under
// root.
func generate(root, docPath string) (current, updated []byte, err error) {
	c, err := extract(root)
	if err != nil {
		return nil, nil, err
	}
	current, err = os.ReadFile(docPath)
	if err != nil {
		return nil, nil, err
	}
	// A Windows checkout can have CRLF line endings.
	current = bytes.ReplaceAll(current, []byte("\r\n"), []byte("\n"))
	updated, err = splice(current, render(c))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", docPath, err)
	}
	return current, updated, nil
}
