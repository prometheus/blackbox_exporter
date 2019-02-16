package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"runtime"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
)

var (
	configReloadSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "blackbox_exporter",
		Name:      "config_last_reload_successful",
		Help:      "Blackbox exporter config loaded successfully.",
	})

	configReloadSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "blackbox_exporter",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})
)

func init() {
	prometheus.MustRegister(configReloadSuccess)
	prometheus.MustRegister(configReloadSeconds)
}

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

func (sc *SafeConfig) ReloadConfig(confFile string) (err error) {
	var c = &Config{}
	defer func() {
		if err != nil {
			configReloadSuccess.Set(0)
		} else {
			configReloadSuccess.Set(1)
			configReloadSeconds.SetToCurrentTime()
		}
	}()

	yamlFile, err := ioutil.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}

	if err := yaml.UnmarshalStrict(yamlFile, c); err != nil {
		return fmt.Errorf("error parsing config file: %s", err)
	}

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
	ValidStatusCodes             []int                   `yaml:"valid_status_codes,omitempty"`
	ValidHTTPVersions            []string                `yaml:"valid_http_versions,omitempty"`
	IPProtocol                   string                  `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback           bool                    `yaml:"ip_protocol_fallback,omitempty"`
	NoFollowRedirects            bool                    `yaml:"no_follow_redirects,omitempty"`
	FailIfSSL                    bool                    `yaml:"fail_if_ssl,omitempty"`
	FailIfNotSSL                 bool                    `yaml:"fail_if_not_ssl,omitempty"`
	Method                       string                  `yaml:"method,omitempty"`
	Headers                      map[string]string       `yaml:"headers,omitempty"`
	FailIfMatchesRegexp          []string                `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp       []string                `yaml:"fail_if_not_matches_regexp,omitempty"`
	FailIfHeaderMatchesRegexp    []HeaderMatch           `yaml:"fail_if_header_matches_regexp,omitempty"`
	FailIfHeaderNotMatchesRegexp []HeaderMatch           `yaml:"fail_if_header_not_matches_regexp,omitempty"`
	Body                         string                  `yaml:"body,omitempty"`
	HTTPClientConfig             config.HTTPClientConfig `yaml:"http_client_config,inline"`
}

type HeaderMatch struct {
	Header       string `yaml:"header,omitempty"`
	Regexp       string `yaml:"regexp,omitempty"`
	AllowMissing bool   `yaml:"allow_missing,omitempty"`
}

type QueryResponse struct {
	Expect   string `yaml:"expect,omitempty"`
	Send     string `yaml:"send,omitempty"`
	StartTLS bool   `yaml:"starttls,omitempty"`
}

type TCPProbe struct {
	IPProtocol         string           `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool             `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string           `yaml:"source_ip_address,omitempty"`
	QueryResponse      []QueryResponse  `yaml:"query_response,omitempty"`
	TLS                bool             `yaml:"tls,omitempty"`
	TLSConfig          config.TLSConfig `yaml:"tls_config,omitempty"`
}

type ICMPProbe struct {
	IPProtocol         string `yaml:"preferred_ip_protocol,omitempty"` // Defaults to "ip6".
	IPProtocolFallback bool   `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string `yaml:"source_ip_address,omitempty"`
	PayloadSize        int    `yaml:"payload_size,omitempty"`
	DontFragment       bool   `yaml:"dont_fragment,omitempty"`
}

type DNSProbe struct {
	IPProtocol         string         `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool           `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string         `yaml:"source_ip_address,omitempty"`
	TransportProtocol  string         `yaml:"transport_protocol,omitempty"`
	QueryName          string         `yaml:"query_name,omitempty"`
	QueryType          string         `yaml:"query_type,omitempty"`   // Defaults to ANY.
	ValidRcodes        []string       `yaml:"valid_rcodes,omitempty"` // Defaults to NOERROR.
	ValidateAnswer     DNSRRValidator `yaml:"validate_answer_rrs,omitempty"`
	ValidateAuthority  DNSRRValidator `yaml:"validate_authority_rrs,omitempty"`
	ValidateAdditional DNSRRValidator `yaml:"validate_additional_rrs,omitempty"`
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
	if s.QueryName == "" {
		return errors.New("query name must be set for DNS module")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain TCPProbe
	if err := unmarshal((*plain)(s)); err != nil {
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
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *ICMPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ICMPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
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

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *HeaderMatch) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HeaderMatch
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if s.Header == "" {
		return errors.New("header name must be set for HTTP header matchers")
	}

	if !s.AllowMissing && s.Regexp == "" {
		return errors.New("regexp must be set for required HTTP headers")
	}

	return nil
}
