package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"runtime"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/common/config"
)

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

func (sc *SafeConfig) ReloadConfig(confFile string, logger log.Logger) (err error) {
	var c = &Config{}

	yamlFile, err := ioutil.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("Error reading config file: %s", err)
	}

	if err := yaml.UnmarshalStrict(yamlFile, c); err != nil {
		return fmt.Errorf("Error parsing config file: %s", err)
	}

	// Check for deprecated preferred_ip_protocol
	c.checkDeprecatedConfig(logger)

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
}

type Module struct {
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	HTTP    HTTPProbe     `yaml:"http,omitempty"`
	TCP     TCPProbe      `yaml:"tcp,omitempty"`
	ICMP    ICMPProbe     `yaml:"icmp,omitempty"`
	DNS     DNSProbe      `yaml:"dns,omitempty"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes       []int                   `yaml:"valid_status_codes,omitempty"`
	ValidHTTPVersions      []string                `yaml:"valid_http_versions,omitempty"`
	PreferredIPProtocol    string                  `yaml:"preferred_ip_protocol,omitempty"` // Deprecated
	IPProtocol             string                  `yaml:"ip_protocol,omitempty"`
	FallbackIPProtocol     bool                    `yaml:"fallback_ip_protocol,omitempty"`
	NoFollowRedirects      bool                    `yaml:"no_follow_redirects,omitempty"`
	FailIfSSL              bool                    `yaml:"fail_if_ssl,omitempty"`
	FailIfNotSSL           bool                    `yaml:"fail_if_not_ssl,omitempty"`
	Method                 string                  `yaml:"method,omitempty"`
	Headers                map[string]string       `yaml:"headers,omitempty"`
	FailIfMatchesRegexp    []string                `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string                `yaml:"fail_if_not_matches_regexp,omitempty"`
	Body                   string                  `yaml:"body,omitempty"`
	HTTPClientConfig       config.HTTPClientConfig `yaml:"http_client_config,inline"`
}

type QueryResponse struct {
	Expect   string `yaml:"expect,omitempty"`
	Send     string `yaml:"send,omitempty"`
	StartTLS bool   `yaml:"starttls,omitempty"`
}

type TCPProbe struct {
	PreferredIPProtocol string           `yaml:"preferred_ip_protocol,omitempty"` // Deprecated
	IPProtocol          string           `yaml:"ip_protocol,omitempty"`
	FallbackIPProtocol  bool             `yaml:"fallback_ip_protocol,omitempty"`
	SourceIPAddress     string           `yaml:"source_ip_address,omitempty"`
	QueryResponse       []QueryResponse  `yaml:"query_response,omitempty"`
	TLS                 bool             `yaml:"tls,omitempty"`
	TLSConfig           config.TLSConfig `yaml:"tls_config,omitempty"`
}

type ICMPProbe struct {
	PreferredIPProtocol string `yaml:"preferred_ip_protocol,omitempty"` // Deprecated
	IPProtocol          string `yaml:"ip_protocol,omitempty"`           // Defaults to "ip6".
	FallbackIPProtocol  bool   `yaml:"fallback_ip_protocol,omitempty"`
	SourceIPAddress     string `yaml:"source_ip_address,omitempty"`
	PayloadSize         int    `yaml:"payload_size,omitempty"`
	DontFragment        bool   `yaml:"dont_fragment,omitempty"`
}

type DNSProbe struct {
	PreferredIPProtocol string         `yaml:"preferred_ip_protocol,omitempty"` // Deprecated
	IPProtocol          string         `yaml:"ip_protocol,omitempty"`
	FallbackIPProtocol  bool           `yaml:"fallback_ip_protocol,omitempty"`
	SourceIPAddress     string         `yaml:"source_ip_address,omitempty"`
	TransportProtocol   string         `yaml:"transport_protocol,omitempty"`
	QueryName           string         `yaml:"query_name,omitempty"`
	QueryType           string         `yaml:"query_type,omitempty"`   // Defaults to ANY.
	ValidRcodes         []string       `yaml:"valid_rcodes,omitempty"` // Defaults to NOERROR.
	ValidateAnswer      DNSRRValidator `yaml:"validate_answer_rrs,omitempty"`
	ValidateAuthority   DNSRRValidator `yaml:"validate_authority_rrs,omitempty"`
	ValidateAdditional  DNSRRValidator `yaml:"validate_additional_rrs,omitempty"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
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
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *HTTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HTTPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	// Remove when preferred_ip_protocol support will be terminated
	if s.PreferredIPProtocol != "" && s.IPProtocol == "" {
		s.IPProtocol = s.PreferredIPProtocol
	}

	if err := s.HTTPClientConfig.Validate(); err != nil {
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

	// Remove when preferred_ip_protocol support will be terminated
	if s.PreferredIPProtocol != "" && s.IPProtocol == "" {
		s.IPProtocol = s.PreferredIPProtocol
	}

	if s.QueryName == "" {
		return errors.New("Query name must be set for DNS module")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain TCPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	// Remove when preferred_ip_protocol support will be terminated
	if s.PreferredIPProtocol != "" && s.IPProtocol == "" {
		s.IPProtocol = s.PreferredIPProtocol
	}

	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSRRValidator) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSRRValidator
	if err := unmarshal((*plain)(s)); err != nil {
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

	// Remove when preferred_ip_protocol support will be terminated
	if s.PreferredIPProtocol != "" && s.IPProtocol == "" {
		s.IPProtocol = s.PreferredIPProtocol
	}

	if runtime.GOOS == "windows" && s.DontFragment {
		return errors.New("\"dont_fragment\" is not supported on windows platforms")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *QueryResponse) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain QueryResponse
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// checkDeprecatedConfig will print a warning about preferred_ip_protocol
func (s *Config) checkDeprecatedConfig(logger log.Logger) {

	for _, module := range s.Modules {
		moduleName := ""
		switch module.Prober {
		case "http":
			if module.HTTP.PreferredIPProtocol != "" {
				moduleName = "http"
			}
		case "tcp":
			if module.TCP.PreferredIPProtocol != "" {
				moduleName = "tcp"
			}
		case "icmp":
			if module.ICMP.PreferredIPProtocol != "" {
				moduleName = "icmp"
			}
		case "dns":
			if module.DNS.PreferredIPProtocol != "" {
				moduleName = "dns"
			}
		}
		if moduleName != "" {
			level.Warn(logger).Log("msg", "Warning deprecated config", "DeprecatedConfig", "preferred_ip_protocol", "NewConfig", "ip_protocol", "Module", moduleName)
		}
	}
}
