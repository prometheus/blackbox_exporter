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

func TestHistoryGetById(t *testing.T) {
	history := &ResultHistory{MaxResults: 2}

	history.Add("module", "target-0", fmt.Sprintf("result %d", history.nextId), true)
	history.Add("module", "target-1", fmt.Sprintf("result %d", history.nextId), false)

	// Get a Result object for a target that exists
	resultTrue := history.GetById(0)
	if resultTrue == nil {
		t.Errorf("Error finding the result in history by id for id: 1")
	} else {
		if resultTrue.Id != 0 {
			t.Errorf("Error finding the result in history by id: expected \"%d\" and got \"%d\"", 0, resultTrue.Id)
		}
	}

	resultFalse := history.GetById(1)
	if resultFalse == nil {
		t.Errorf("Error finding the result in history by id for id: 1")
	} else {
		if resultFalse.Id != 1 {
			t.Errorf("Error finding the result in history by id: expected \"%d\" and got \"%d\"", 1, resultFalse.Id)
		}
	}

	// Get a Result object for a target that doesn't exist
	if history.GetById(5) != nil {
		t.Errorf("Error finding the result in history by id for id: 5")
	}
}

func TestHistoryGetByTarget(t *testing.T) {
	history := &ResultHistory{MaxResults: 3}

	history.Add("module-0", "target-0", fmt.Sprintf("result %d", history.nextId), true)
	history.Add("module-1", "target-1", fmt.Sprintf("result %d", history.nextId), false)
	history.Add("module-0", "target-1", fmt.Sprintf("result %d", history.nextId), false)

	// Get a Result object for a target that exists
	resultTrue := history.GetByTarget("target-0", "")
	if resultTrue == nil {
		t.Errorf("Error finding the result in history by target for target-0")
	} else {
		if resultTrue.Target != "target-0" {
			t.Errorf("Error finding the result in history by target for target: expected \"%s\" and got \"%s\"", "target-0", resultTrue.Target)
		}
	}

	// Get a result object for a non-unique target (same target via multiple modules)
	// should return the match that was first inserted
	resultFalse := history.GetByTarget("target-1", "")
	if resultFalse == nil {
		t.Errorf("Error finding the result in history by target for target-1")
	} else {
		if resultFalse.Target != "target-1" {
			t.Errorf("Error finding the result in history by target for target: expected \"%s\" and got \"%s\"", "target-1", resultFalse.Target)
		}
		if resultFalse.ModuleName != "module-1" {
			t.Errorf("Error finding the result in history by target for target: expected \"%s\" and got \"%s\"", "module-1", resultFalse.ModuleName)
		}
	}

	// Get a result object for a non-unique target (same target via multiple modules)
	// should return the match that was first inserted
	alternate_history := &ResultHistory{MaxResults: 3}
	alternate_history.Add("module-0", "target-0", fmt.Sprintf("result %d", alternate_history.nextId), true)
	alternate_history.Add("module-0", "target-1", fmt.Sprintf("result %d", alternate_history.nextId), false)
	alternate_history.Add("module-1", "target-1", fmt.Sprintf("result %d", alternate_history.nextId), false)
	resultFalse = alternate_history.GetByTarget("target-1", "")
	if resultFalse == nil {
		t.Errorf("Error finding the result in history by target for target-1")
	} else {
		if resultFalse.Target != "target-1" {
			t.Errorf("Error finding the result in history by target for target: expected \"%s\" and got \"%s\"", "target-1", resultFalse.Target)
		}
		if resultFalse.ModuleName != "module-0" {
			t.Errorf("Error finding the result in history by target for target: expected \"%s\" and got \"%s\"", "module-1", resultFalse.ModuleName)
		}
	}
}

func TestHistoryGetByTargetAndModule(t *testing.T) {
	history := &ResultHistory{MaxResults: 3}

	history.Add("module-0", "target-0", fmt.Sprintf("result %d", history.nextId), true)
	history.Add("module-1", "target-1", fmt.Sprintf("result %d", history.nextId), false)
	history.Add("module-0", "target-1", fmt.Sprintf("result %d", history.nextId), false)

	// Get a result by existing target and non-matching module
	if history.GetByTarget("target-1", "module-5") != nil {
		t.Errorf("Incorrectly found a result in history by target for [target-1,module-5]")
	}

	// Get a result by existing target and matching module
	if result := history.GetByTarget("target-1", "module-1"); result == nil {
		t.Errorf("Incorrectly found no result in history by target for [target-1,module-1]")
	} else {
		if result.Target != "target-1" {
			t.Errorf("Error finding the result in history by target and module for target: expected \"%s\" and got \"%s\"", "target-1", result.Target)
		}
		if result.ModuleName != "module-1" {
			t.Errorf("Error finding the result in history by target and module for target: expected \"%s\" and got \"%s\"", "module-1", result.ModuleName)
		}
	}
}
