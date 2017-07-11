package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/config"
)

type Config struct {
	Modules map[string]Module `yaml:"modules"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

type Module struct {
	Prober  string        `yaml:"prober"`
	Timeout time.Duration `yaml:"timeout"`
	HTTP    HTTPProbe     `yaml:"http"`
	TCP     TCPProbe      `yaml:"tcp"`
	ICMP    ICMPProbe     `yaml:"icmp"`
	DNS     DNSProbe      `yaml:"dns"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes       []int                   `yaml:"valid_status_codes,omitempty"`
	ValidHTTPVersions      []string                `yaml:"valid_http_versions,omitempty"`
	PreferredIPProtocol    string                  `yaml:"preferred_ip_protocol,omitempty"`
	NoFollowRedirects      bool                    `yaml:"no_follow_redirects,omitempty"`
	FailIfSSL              bool                    `yaml:"fail_if_ssl,omitempty"`
	FailIfNotSSL           bool                    `yaml:"fail_if_not_ssl,omitempty"`
	Method                 string                  `yaml:"method,omitempty"`
	Headers                map[string]string       `yaml:"headers,omitempty"`
	FailIfMatchesRegexp    []string                `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string                `yaml:"fail_if_not_matches_regexp,omitempty"`
	Body                   string                  `yaml:"body,omitempty"`
	HTTPClientConfig       config.HTTPClientConfig `yaml:"http_client_config,inline,omitempty"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type QueryResponse struct {
	Expect string `yaml:"expect"`
	Send   string `yaml:"send"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type TCPProbe struct {
	PreferredIPProtocol string           `yaml:"preferred_ip_protocol"`
	QueryResponse       []QueryResponse  `yaml:"query_response"`
	TLS                 bool             `yaml:"tls"`
	TLSConfig           config.TLSConfig `yaml:"tls_config"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type ICMPProbe struct {
	PreferredIPProtocol string `yaml:"preferred_ip_protocol"` // Defaults to "ip6".

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type DNSProbe struct {
	PreferredIPProtocol string         `yaml:"preferred_ip_protocol"`
	TransportProtocol   string         `yaml:"transport_protocol"`
	QueryName           string         `yaml:"query_name"`
	QueryType           string         `yaml:"query_type"`   // Defaults to ANY.
	ValidRcodes         []string       `yaml:"valid_rcodes"` // Defaults to NOERROR.
	ValidateAnswer      DNSRRValidator `yaml:"validate_answer_rrs"`
	ValidateAuthority   DNSRRValidator `yaml:"validate_authority_rrs"`
	ValidateAdditional  DNSRRValidator `yaml:"validate_additional_rrs"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

func checkOverflow(m map[string]interface{}, ctx string) error {
	if len(m) > 0 {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		return fmt.Errorf("unknown fields in %s: %s", ctx, strings.Join(keys, ", "))
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "config"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Module
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "module"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *HTTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HTTPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "http probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "dns probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain TCPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "tcp probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSRRValidator) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSRRValidator
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "dns rr validator"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *ICMPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ICMPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "icmp probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *QueryResponse) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain QueryResponse
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "query response"); err != nil {
		return err
	}
	return nil
}
