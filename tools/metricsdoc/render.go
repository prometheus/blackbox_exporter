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
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	beginMarker = `<!-- BEGIN GENERATED METRICS: run "make metrics-docs" -->`
	endMarker   = `<!-- END GENERATED METRICS -->`
)

// render returns the generated Markdown that goes between the markers.
func render(c *catalog) []byte {
	var b bytes.Buffer
	b.WriteString("## Exporter metrics\n\n")
	b.WriteString("Served on `/metrics`.\n\n")
	writeTable(&b, filter(c.Metrics, func(m *metric) bool { return m.Exporter }))

	b.WriteString("\n## Metrics returned by every probe\n\n")
	b.WriteString("Returned by `/probe` for every module, whatever its prober.\n\n")
	writeTable(&b, filter(c.Metrics, func(m *metric) bool { return m.EveryProbe }))

	probeMetrics := filter(c.Metrics, func(m *metric) bool { return len(m.Probers) > 0 })
	b.WriteString("\n## Metrics by prober\n\n")
	b.WriteString("A ✓ means that the prober can return the metric.\n\n")
	b.WriteString("| Metric |")
	for _, p := range c.Probers {
		fmt.Fprintf(&b, " %s |", p)
	}
	b.WriteString("\n|---|" + strings.Repeat(":-:|", len(c.Probers)) + "\n")
	for _, m := range probeMetrics {
		fmt.Fprintf(&b, "| `%s` |", m.Name)
		for _, p := range c.Probers {
			if slices.Contains(m.Probers, p) {
				b.WriteString(" ✓ |")
			} else {
				b.WriteString(" |")
			}
		}
		b.WriteString("\n")
	}

	for _, p := range c.Probers {
		fmt.Fprintf(&b, "\n### %s\n\n", p)
		ms := filter(probeMetrics, func(m *metric) bool { return slices.Contains(m.Probers, p) })
		if len(ms) == 0 {
			b.WriteString("No metrics besides the ones returned by every probe.\n")
			continue
		}
		writeTable(&b, ms)
	}
	return b.Bytes()
}

func filter(ms []*metric, keep func(*metric) bool) []*metric {
	var out []*metric
	for _, m := range ms {
		if keep(m) {
			out = append(out, m)
		}
	}
	return out
}

func writeTable(b *bytes.Buffer, ms []*metric) {
	b.WriteString("| Metric | Type | Labels | Help |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, m := range ms {
		var labels string
		if m.LabelsFrom != "" {
			labels = fmt.Sprintf("names set by `%s`", m.LabelsFrom)
		} else {
			quoted := make([]string, len(m.Labels))
			for i, l := range m.Labels {
				quoted[i] = "`" + l + "`"
			}
			labels = strings.Join(quoted, ", ")
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", m.Name, m.Type, labels, escapeCell(m.Help))
	}
}

var cellEscaper = strings.NewReplacer("\n", " ", "|", `\|`, "<", "&lt;", ">", "&gt;")

func escapeCell(s string) string {
	return cellEscaper.Replace(s)
}

// splice replaces the text between the markers in doc with generated and
// keeps everything outside the markers byte for byte.
func splice(doc, generated []byte) ([]byte, error) {
	begin, end := []byte(beginMarker), []byte(endMarker)
	switch {
	case bytes.Count(doc, begin) != 1:
		return nil, fmt.Errorf("want exactly one %s line, found %d", beginMarker, bytes.Count(doc, begin))
	case bytes.Count(doc, end) != 1:
		return nil, fmt.Errorf("want exactly one %s line, found %d", endMarker, bytes.Count(doc, end))
	}
	start := bytes.Index(doc, begin) + len(begin)
	stop := bytes.Index(doc, end)
	if stop < start {
		return nil, errors.New("the end marker comes before the begin marker")
	}
	var b bytes.Buffer
	b.Write(doc[:start])
	b.WriteString("\n\n")
	b.Write(bytes.TrimRight(generated, "\n"))
	b.WriteString("\n\n")
	b.Write(doc[stop:])
	return b.Bytes(), nil
}
