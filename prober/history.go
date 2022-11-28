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
	"sync"
)

// Result contains the result of the execution of a probe
type Result struct {
	Id          int64
	ModuleName  string
	Target      string
	DebugOutput string
	Success     bool
}

// ResultHistory contains two history slices: `results` contains most recent `maxResults` results.
// After they expire out of `results`, failures will be saved in `preservedFailedResults`. This
// ensures that we are always able to see debug information about recent failures.
type ResultHistory struct {
	mu                     sync.Mutex
	nextId                 int64
	results                []*Result
	preservedFailedResults []*Result
	MaxResults             uint
}

// Add a result to the history.
func (rh *ResultHistory) Add(moduleName, target, debugOutput string, success bool) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	r := &Result{
		Id:          rh.nextId,
		ModuleName:  moduleName,
		Target:      target,
		DebugOutput: debugOutput,
		Success:     success,
	}
	rh.nextId++

	rh.results = append(rh.results, r)
	if uint(len(rh.results)) > rh.MaxResults {
		// If we are about to remove a failure, add it to the failed result history, then
		// remove the oldest failed result, if needed.
		if !rh.results[0].Success {
			rh.preservedFailedResults = append(rh.preservedFailedResults, rh.results[0])
			if uint(len(rh.preservedFailedResults)) > rh.MaxResults {
				preservedFailedResults := make([]*Result, len(rh.preservedFailedResults)-1)
				copy(preservedFailedResults, rh.preservedFailedResults[1:])
				rh.preservedFailedResults = preservedFailedResults
			}
		}
		results := make([]*Result, len(rh.results)-1)
		copy(results, rh.results[1:])
		rh.results = results
	}
}

// List returns a list of all results.
func (rh *ResultHistory) List() []*Result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	// Results in each slice are disjoint. We can simply concatenate the results.
	return append(rh.preservedFailedResults[:], rh.results...)
}

// Get returns a given result.
func (rh *ResultHistory) Get(id int64) *Result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	for _, r := range rh.preservedFailedResults {
		if r.Id == id {
			return r
		}
	}
	for _, r := range rh.results {
		if r.Id == id {
			return r
		}
	}

	return nil
}
