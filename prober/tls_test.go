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

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestGetLastChainExpiry(t *testing.T) {
	tests := []struct {
		name  string
		state *tls.ConnectionState
		want  time.Time
	}{
		{
			name:  "no verified chains (e.g. insecure_skip_verify)",
			state: &tls.ConnectionState{VerifiedChains: nil},
			want:  time.Time{},
		},
		{
			name: "single verified chain",
			state: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{{NotAfter: time.Unix(1000, 0)}},
				},
			},
			want: time.Unix(1000, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLastChainExpiry(tt.state)
			if !got.Equal(tt.want) {
				t.Errorf("getLastChainExpiry() = %v, want %v", got, tt.want)
			}
			if tt.want.IsZero() != got.IsZero() {
				t.Errorf("getLastChainExpiry().IsZero() = %v, want %v", got.IsZero(), tt.want.IsZero())
			}
		})
	}
}
