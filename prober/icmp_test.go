// Copyright 2016 The Prometheus Authors
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

import "testing"

// TestGetICMPSequence verifies the sequence counter increments and wraps at the
// 16-bit boundary.
func TestGetICMPSequence(t *testing.T) {
	tests := []struct {
		name  string
		start uint16
		want  uint16
	}{
		{name: "increments from zero", start: 0, want: 1},
		{name: "increments mid-range", start: 41, want: 42},
		{name: "wraps at uint16 max", start: 0xffff, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			icmpSequenceMutex.Lock()
			icmpSequence = tc.start
			icmpSequenceMutex.Unlock()

			if got := getICMPSequence(); got != tc.want {
				t.Errorf("getICMPSequence() with start %d = %d, want %d", tc.start, got, tc.want)
			}
		})
	}
}

// TestGetICMPSequenceMonotonic verifies consecutive calls advance by one.
func TestGetICMPSequenceMonotonic(t *testing.T) {
	icmpSequenceMutex.Lock()
	icmpSequence = 1000
	icmpSequenceMutex.Unlock()

	prev := getICMPSequence()
	for i := 0; i < 100; i++ {
		got := getICMPSequence()
		if got != prev+1 {
			t.Fatalf("call %d: got %d, want %d", i, got, prev+1)
		}
		prev = got
	}
}

// TestGetRandomICMPID verifies IDs stay within the 16-bit ICMP identifier range
// and are not constant.
func TestGetRandomICMPID(t *testing.T) {
	const iterations = 1000
	seen := make(map[int]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		id := getRandomICMPID()
		if id < 0 || id >= 1<<16 {
			t.Fatalf("getRandomICMPID() = %d, want within [0, 65535]", id)
		}
		seen[id] = struct{}{}
	}
	// With 1000 draws over 65536 values, a single fixed value is astronomically
	// unlikely; this guards against a broken generator returning a constant.
	if len(seen) < 2 {
		t.Errorf("getRandomICMPID() produced %d distinct values over %d calls, want a varied distribution", len(seen), iterations)
	}
}
