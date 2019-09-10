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

package main

import (
	"fmt"
	"testing"
)

func TestHistoryKeepsLatestResults(t *testing.T) {
	history := &resultHistory{maxResults: 3}
	for i := 0; i < 4; i++ {
		history.Add("module", "target", fmt.Sprintf("result %d", i), true)
	}

	savedResults := history.List()
	for i := 0; i < len(savedResults); i++ {
		if savedResults[i].debugOutput != fmt.Sprintf("result %d", i+1) {
			t.Errorf("History contained the wrong result at index %d", i)
		}
	}
}

func FillHistoryWithMaxSuccesses(h *resultHistory) {
	for i := uint(0); i < h.maxResults; i++ {
		h.Add("module", "target", fmt.Sprintf("result %d", h.nextId), true)
	}
}

func FillHistoryWithMaxPreservedFailures(h *resultHistory) {
	for i := uint(0); i < h.maxResults; i++ {
		h.Add("module", "target", fmt.Sprintf("result %d", h.nextId), false)
	}
}

func TestHistoryPreservesExpiredFailedResults(t *testing.T) {
	history := &resultHistory{maxResults: 3}

	// Success are expired, no failues are expired
	FillHistoryWithMaxSuccesses(history)
	FillHistoryWithMaxPreservedFailures(history)
	savedResults := history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.maxResults)
		if savedResults[i].debugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected: %s, Actual: %s", i, expectedDebugOutput, savedResults[i].debugOutput)
		}
	}

	// Failures are expired, should all be preserved
	FillHistoryWithMaxPreservedFailures(history)
	savedResults = history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.maxResults)
		if savedResults[i].debugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected: %s, Actual: %s", i, expectedDebugOutput, savedResults[i].debugOutput)
		}
	}

	// New expired failures are preserved, new success are not expired
	FillHistoryWithMaxPreservedFailures(history)
	FillHistoryWithMaxSuccesses(history)
	savedResults = history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.maxResults*3)
		if savedResults[i].debugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected: %s, Actual: %s", i, expectedDebugOutput, savedResults[i].debugOutput)
		}
	}
}
