// Copyright 2017 The Prometheus Authors
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

package prober

import (
	"fmt"
	"testing"
)

func TestHistoryKeepsLatestResults(t *testing.T) {
	history := &ResultHistory{MaxResults: 3}
	for i := 0; i < 4; i++ {
		history.Add("module", "target", fmt.Sprintf("result %d", i), true)
	}

	savedResults := history.List()
	for i := 0; i < len(savedResults); i++ {
		if savedResults[i].DebugOutput != fmt.Sprintf("result %d", i+1) {
			t.Errorf("History contained the wrong result at index %d", i)
		}
	}
}

func FillHistoryWithMaxSuccesses(h *ResultHistory) {
	for i := uint(0); i < h.MaxResults; i++ {
		h.Add("module", "target", fmt.Sprintf("result %d", h.nextId), true)
	}
}

func FillHistoryWithMaxPreservedFailures(h *ResultHistory) {
	for i := uint(0); i < h.MaxResults; i++ {
		h.Add("module", "target", fmt.Sprintf("result %d", h.nextId), false)
	}
}

func TestHistoryPreservesExpiredFailedResults(t *testing.T) {
	history := &ResultHistory{MaxResults: 3}

	// Success are expired, no failures are expired
	FillHistoryWithMaxSuccesses(history)
	FillHistoryWithMaxPreservedFailures(history)
	savedResults := history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.MaxResults)
		if savedResults[i].DebugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected: %s, Actual: %s", i, expectedDebugOutput, savedResults[i].DebugOutput)
		}
	}

	// Failures are expired, should all be preserved
	FillHistoryWithMaxPreservedFailures(history)
	savedResults = history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.MaxResults)
		if savedResults[i].DebugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected: %s, Actual: %s", i, expectedDebugOutput, savedResults[i].DebugOutput)
		}
	}

	// New expired failures are preserved, new success are not expired
	FillHistoryWithMaxPreservedFailures(history)
	FillHistoryWithMaxSuccesses(history)
	savedResults = history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.MaxResults*3)
		if savedResults[i].DebugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected: %s, Actual: %s", i, expectedDebugOutput, savedResults[i].DebugOutput)
		}
	}
}
