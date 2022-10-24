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

package config

import (
	"errors"
	"net"
	"strings"

	"github.com/yl2chen/cidranger"
)

// IPFilter is used to filter network traffic so that
// probes are limited in the destination addresses they
// can probe.
//
// The configuration looks like:
//
//	  ip_filter:
//		   default: allow|deny
//		   allowed:
//		     [... list of networks in CIDR format ...]
//		   denied:
//		     [... list of networks in CIDR format ...]
//
// The longest prefix match takes precedence:
//
//	ip_filter:
//	  default: deny
//	  allowed:
//	    - 10.0.0.0/8
//	  denied:
//	    - 10.0.1.0/24
//
// Only traffic to 10.0.0.0/8 is allowed, except the 10.0.1.0/24
// subnet, which is blocked.
//
// The default key is only mandatory when both allowed and denied
// are defined. Otherwise, it is implicitly deny or allow.
type IPFilter struct {
	ranger       cidranger.Ranger
	allowed      []net.IPNet
	denied       []net.IPNet
	defaultAllow bool
}

// NewIPFilter creates a new IPFilter object with the given configuration.
func NewIPFilter(allowed []net.IPNet, denied []net.IPNet, defaultAllow bool) (*IPFilter, error) {
	f := &IPFilter{
		ranger:       cidranger.NewPCTrieRanger(),
		defaultAllow: defaultAllow,
		allowed:      allowed,
		denied:       denied,
	}
	if err := f.insert(allowed, true); err != nil {
		return nil, err
	}
	if err := f.insert(denied, false); err != nil {
		return nil, err
	}
	return f, nil
}

// IsAllowed returns if the IP address is allowed by the filter.
// A nil or zero-value filter allows all traffic.
func (f *IPFilter) IsAllowed(ip net.IP) bool {
	if f == nil || f.ranger == nil {
		return true
	}
	lst, err := f.ranger.ContainingNetworks(ip)
	if err != nil || len(lst) < 1 {
		return f.defaultAllow
	}
	return lst[len(lst)-1].(filterEntry).allow
}

// UnmarshalYAML constructs an IPFilter from its YAML definition.
func (f *IPFilter) UnmarshalYAML(decode func(interface{}) error) error {
	var base struct {
		DefValue *string  `yaml:"default"`
		Allowed  []string `yaml:"allowed"`
		Denied   []string `yaml:"denied"`
	}
	err := decode(&base)
	if err != nil {
		return err
	}

	defAllow := len(base.Allowed) == 0
	if base.DefValue == nil && len(base.Allowed) > 0 && len(base.Denied) > 0 {
		return errors.New("missing field ip_filter.default")
	}
	if base.DefValue != nil {
		switch strings.ToLower(*base.DefValue) {
		case "allow", "allowed":
			defAllow = true
		case "deny", "denied", "block", "blocked":
			defAllow = false
		default:
			return errors.New("unsupported value for ip_filter.default, use `allowed` or `denied`")
		}
	}
	allowed, err := parseCIDRNets(base.Allowed)
	if err != nil {
		return err
	}
	denied, err := parseCIDRNets(base.Denied)
	if err != nil {
		return err
	}
	filter, err := NewIPFilter(allowed, denied, defAllow)
	if err != nil {
		return err
	}
	*f = *filter
	return err
}

// MarshalYAML returns the YAML representation of the IPFilter.
func (f *IPFilter) MarshalYAML() (interface{}, error) {
	if f == nil || f.ranger == nil {
		return nil, nil
	}
	body := make(map[string]interface{})
	hasAllowed := len(f.allowed) > 0
	hasDenied := len(f.denied) > 0
	if hasAllowed {
		body["allowed"] = netsToString(f.allowed)
	}
	if hasDenied {
		body["denied"] = netsToString(f.denied)
	}
	if (hasAllowed && hasDenied) || f.defaultAllow != !hasAllowed {
		body["default"] = "deny"
		if f.defaultAllow {
			body["default"] = "allow"
		}
	}
	return body, nil
}

func (f *IPFilter) insert(lst []net.IPNet, allow bool) error {
	for _, nt := range lst {
		if err := f.ranger.Insert(filterEntry{
			net:   nt,
			allow: allow,
		}); err != nil {
			return err
		}
	}
	return nil
}

func parseCIDRNets(lst []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, len(lst))

	for i, s := range lst {
		_, nt, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		out[i] = *nt
	}
	return out, nil
}

func netsToString(lst []net.IPNet) []string {
	r := make([]string, len(lst))
	for i, n := range lst {
		r[i] = n.String()
	}
	return r
}

type filterEntry struct {
	net   net.IPNet
	allow bool
}

var _ cidranger.RangerEntry = filterEntry{}

func (e filterEntry) Network() net.IPNet {
	return e.net
}
