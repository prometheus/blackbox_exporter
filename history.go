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
	"sync"
)

type result struct {
	id          int64
	moduleName  string
	target      string
	debugOutput string
	success     bool
}

type resultHistory struct {
	mu         sync.Mutex
	nextId     int64
	results    []*result
	maxResults uint
}

// Add a result to the history.
func (rh *resultHistory) Add(moduleName, target, debugOutput string, success bool) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	r := &result{
		id:          rh.nextId,
		moduleName:  moduleName,
		target:      target,
		debugOutput: debugOutput,
		success:     success,
	}
	rh.nextId++

	rh.results = append(rh.results, r)
	if uint(len(rh.results)) > rh.maxResults {
		results := make([]*result, len(rh.results)-1)
		copy(results, rh.results[1:])
		rh.results = results
	}
}

// List returns a list of all results.
func (rh *resultHistory) List() []*result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	return rh.results[:]
}

// Get returns a given result.
func (rh *resultHistory) Get(id int64) *result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	for _, r := range rh.results {
		if r.id == id {
			return r
		}
	}

	return nil
}
