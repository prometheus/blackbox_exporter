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
	"fmt"
	"math"
	"net/textproto"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/alecthomas/units"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/config"
)

var (
	// DefaultModule set default configuration for the Module
	DefaultModule = Module{
		HTTP: DefaultHTTPProbe,
		TCP:  DefaultTCPProbe,
		ICMP: DefaultICMPProbe,
		DNS:  DefaultDNSProbe,
	}

	// DefaultHTTPProbe set default value for HTTPProbe
	DefaultHTTPProbe = HTTPProbe{
		IPProtocolFallback: true,
		HTTPClientConfig:   config.DefaultHTTPClientConfig,
	}

	// DefaultGRPCProbe set default value for HTTPProbe
	DefaultGRPCProbe = GRPCProbe{
		Service:            "",
		IPProtocolFallback: true,
	}

	// DefaultTCPProbe set default value for TCPProbe
	DefaultTCPProbe = TCPProbe{
		IPProtocolFallback: true,
	}

	// DefaultICMPProbe set default value for ICMPProbe
	DefaultICMPTTL   = 64
	DefaultICMPProbe = ICMPProbe{
		IPProtocolFallback: true,
		TTL:                DefaultICMPTTL,
	}

	// DefaultDNSProbe set default value for DNSProbe
	DefaultDNSProbe = DNSProbe{
		IPProtocolFallback: true,
		Recursion:          true,
	}
)

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type SafeConfig struct {
	sync.RWMutex
	C                   *Config
	configReloadSuccess prometheus.Gauge
	configReloadSeconds prometheus.Gauge
}

func NewSafeConfig(reg prometheus.Registerer) *SafeConfig {
	configReloadSuccess := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Namespace: "blackbox_exporter",
		Name:      "config_last_reload_successful",
		Help:      "Blackbox exporter config loaded successfully.",
	})

	configReloadSeconds := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Namespace: "blackbox_exporter",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})
	return &SafeConfig{C: &Config{}, configReloadSuccess: configReloadSuccess, configReloadSeconds: configReloadSeconds}
}

func (sc *SafeConfig) ReloadConfig(confFile string, logger log.Logger) (err error) {
	var c = &Config{}
	defer func() {
		if err != nil {
			sc.configReloadSuccess.Set(0)
		} else {
			sc.configReloadSuccess.Set(1)
			sc.configReloadSeconds.SetToCurrentTime()
		}
	}()

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(c); err != nil {
		return fmt.Errorf("error parsing config file: %s", err)
	}

	for name, module := range c.Modules {
		if module.HTTP.NoFollowRedirects != nil {
			// Hide the old flag from the /config page.
			module.HTTP.NoFollowRedirects = nil
			c.Modules[name] = module
			if logger != nil {
				level.Warn(logger).Log("msg", "no_follow_redirects is deprecated and will be removed in the next release. It is replaced by follow_redirects.", "module", name)
			}
		}
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
	original string
}

// NewRegexp creates a new anchored Regexp and returns an error if the
// passed-in regular expression does not compile.
func NewRegexp(s string) (Regexp, error) {
	regex, err := regexp.Compile(s)
	return Regexp{
		Regexp:   regex,
		original: s,
	}, err
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	r, err := NewRegexp(s)
	if err != nil {
		return fmt.Errorf("\"Could not compile regular expression\" regexp=\"%s\"", s)
	}
	*re = r
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (re Regexp) MarshalYAML() (interface{}, error) {
	if re.original != "" {
		return re.original, nil
	}
	return nil, nil
}

// MustNewRegexp works like NewRegexp, but panics if the regular expression does not compile.
func MustNewRegexp(s string) Regexp {
	re, err := NewRegexp(s)
	if err != nil {
		panic(err)
	}
	return re
}

type Module struct {
	Prober  string        `yaml:"prober,omitempty" query:"prober"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	HTTP    HTTPProbe     `yaml:"http,omitempty"`
	TCP     TCPProbe      `yaml:"tcp,omitempty"`
	ICMP    ICMPProbe     `yaml:"icmp,omitempty"`
	DNS     DNSProbe      `yaml:"dns,omitempty"`
	GRPC    GRPCProbe     `yaml:"grpc,omitempty"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes             []int                   `yaml:"valid_status_codes,omitempty" query:"http.valid_status_codes[]"`
	ValidHTTPVersions            []string                `yaml:"valid_http_versions,omitempty" query:"http.valid_http_versions[]"`
	IPProtocol                   string                  `yaml:"preferred_ip_protocol,omitempty" query:"http.preferred_ip_protocol"`
	IPProtocolFallback           bool                    `yaml:"ip_protocol_fallback,omitempty" query:"http.ip_protocol_fallback"`
	SkipResolvePhaseWithProxy    bool                    `yaml:"skip_resolve_phase_with_proxy,omitempty" query:"http.skip_resolve_phase_with_proxy"`
	NoFollowRedirects            *bool                   `yaml:"no_follow_redirects,omitempty" query:"http.no_follow_redirects"`
	FailIfSSL                    bool                    `yaml:"fail_if_ssl,omitempty" query:"http.fail_if_ssl"`
	FailIfNotSSL                 bool                    `yaml:"fail_if_not_ssl,omitempty" query:"http.fail_if_not_ssl"`
	Method                       string                  `yaml:"method,omitempty" query:"http.method"`
	Headers                      map[string]string       `yaml:"headers,omitempty" query:"http.headers"`
	FailIfBodyMatchesRegexp      []Regexp                `yaml:"fail_if_body_matches_regexp,omitempty" query:"http.fail_if_body_matches_regexp[]"`
	FailIfBodyNotMatchesRegexp   []Regexp                `yaml:"fail_if_body_not_matches_regexp,omitempty" query:"http.fail_if_body_not_matches_regexp[]"`
	FailIfHeaderMatchesRegexp    []HeaderMatch           `yaml:"fail_if_header_matches,omitempty" query:"http.fail_if_header_matches[]"`
	FailIfHeaderNotMatchesRegexp []HeaderMatch           `yaml:"fail_if_header_not_matches,omitempty" query:"http.fail_if_header_not_matches[]"`
	Body                         string                  `yaml:"body,omitempty" query:"http.body"`
	BodyFile                     string                  `yaml:"body_file,omitempty"`
	HTTPClientConfig             config.HTTPClientConfig `yaml:"http_client_config,inline" query:"http.http_client_config"`
	Compression                  string                  `yaml:"compression,omitempty" query:"http.compression"`
	BodySizeLimit                units.Base2Bytes        `yaml:"body_size_limit,omitempty" query:"http.body_size_limit"`
}

type GRPCProbe struct {
	Service             string           `yaml:"service,omitempty" query:"grpc.service"`
	TLS                 bool             `yaml:"tls,omitempty" query:"grpc.tls"`
	TLSConfig           config.TLSConfig `yaml:"tls_config,omitempty" query:"grpc.tls_config"`
	IPProtocolFallback  bool             `yaml:"ip_protocol_fallback,omitempty" query:"grpc.ip_protocol_fallback"`
	PreferredIPProtocol string           `yaml:"preferred_ip_protocol,omitempty" query:"grpc.preferred_ip_protocols"`
}

type HeaderMatch struct {
	Header       string `yaml:"header,omitempty"`
	Regexp       Regexp `yaml:"regexp,omitempty"`
	AllowMissing bool   `yaml:"allow_missing,omitempty"`
}

type QueryResponse struct {
	Expect   Regexp `yaml:"expect,omitempty"`
	Send     string `yaml:"send,omitempty"`
	StartTLS bool   `yaml:"starttls,omitempty"`
}

type TCPProbe struct {
	IPProtocol         string           `yaml:"preferred_ip_protocol,omitempty" query:"tcp.preferred_ip_protocol"`
	IPProtocolFallback bool             `yaml:"ip_protocol_fallback,omitempty" query:"tcp.ip_protocol_fallback"`
	SourceIPAddress    string           `yaml:"source_ip_address,omitempty" query:"tcp.source_ip_address"`
	QueryResponse      []QueryResponse  `yaml:"query_response,omitempty" query:"tcp.query_response[]"`
	TLS                bool             `yaml:"tls,omitempty" query:"tcp.tls"`
	TLSConfig          config.TLSConfig `yaml:"tls_config,omitempty" query:"tcp.tls_config"`
}

type ICMPProbe struct {
	IPProtocol         string `yaml:"preferred_ip_protocol,omitempty" query:"icmp.preferred_ip_protocol"` // Defaults to "ip6".
	IPProtocolFallback bool   `yaml:"ip_protocol_fallback,omitempty" query:"icmp.ip_protocol_fallback"`
	SourceIPAddress    string `yaml:"source_ip_address,omitempty" query:"icmp.source_ip_address"`
	PayloadSize        int    `yaml:"payload_size,omitempty" query:"icmp.payload_size"`
	DontFragment       bool   `yaml:"dont_fragment,omitempty" query:"icmp.dont_fragment"`
	TTL                int    `yaml:"ttl,omitempty" query:"icmp.ttl"`
}

type DNSProbe struct {
	IPProtocol         string           `yaml:"preferred_ip_protocol,omitempty" query:"dns.preferred_ip_protocol"`
	IPProtocolFallback bool             `yaml:"ip_protocol_fallback,omitempty" query:"dns.ip_protocol_fallback"`
	DNSOverTLS         bool             `yaml:"dns_over_tls,omitempty" query:"dns.dns_over_tls"`
	TLSConfig          config.TLSConfig `yaml:"tls_config,omitempty" query:"dns.tls_config"`
	SourceIPAddress    string           `yaml:"source_ip_address,omitempty" query:"dns.source_ip_address"`
	TransportProtocol  string           `yaml:"transport_protocol,omitempty" query:"dns.transport_protocol"`
	QueryClass         string           `yaml:"query_class,omitempty" query:"dns.query_class"` // Defaults to IN.
	QueryName          string           `yaml:"query_name,omitempty" query:"dns.query_name"`
	QueryType          string           `yaml:"query_type,omitempty" query:"dns.query_type"`               // Defaults to ANY.
	Recursion          bool             `yaml:"recursion_desired,omitempty" query:"dns.recursion_desired"` // Defaults to true.
	ValidRcodes        []string         `yaml:"valid_rcodes,omitempty" query:"dns.valid_rcodes[]"`         // Defaults to NOERROR.
	ValidateAnswer     DNSRRValidator   `yaml:"validate_answer_rrs,omitempty" query:"dns.validate_answer_rrs"`
	ValidateAuthority  DNSRRValidator   `yaml:"validate_authority_rrs,omitempty" query:"dns.validate_authority_rrs"`
	ValidateAdditional DNSRRValidator   `yaml:"validate_additional_rrs,omitempty" query:"dns.validate_additional_rrs"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp     []string `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfAllMatchRegexp    []string `yaml:"fail_if_all_match_regexp,omitempty"`
	FailIfNotMatchesRegexp  []string `yaml:"fail_if_not_matches_regexp,omitempty"`
	FailIfNoneMatchesRegexp []string `yaml:"fail_if_none_matches_regexp,omitempty"`
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
	*s = DefaultModule
	type plain Module
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *HTTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultHTTPProbe
	type plain HTTPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

func (s *HTTPProbe) Validate() error {
	// BodySizeLimit == 0 means no limit. By leaving it at 0 we
	// avoid setting up the limiter.
	if s.BodySizeLimit < 0 || s.BodySizeLimit == math.MaxInt64 {
		// The implementation behind http.MaxBytesReader tries
		// to add 1 to the specified limit causing it to wrap
		// around and become negative, and then it tries to use
		// that result to index an slice.
		s.BodySizeLimit = math.MaxInt64 - 1
	}

	if err := s.HTTPClientConfig.Validate(); err != nil {
		return err
	}

	if s.NoFollowRedirects != nil {
		s.HTTPClientConfig.FollowRedirects = !*s.NoFollowRedirects
	}

	if s.Body != "" && s.BodyFile != "" {
		return errors.New("setting body and body_file both are not allowed")
	}

	for key, value := range s.Headers {
		switch textproto.CanonicalMIMEHeaderKey(key) {
		case "Accept-Encoding":
			if !isCompressionAcceptEncodingValid(s.Compression, value) {
				return fmt.Errorf(`invalid configuration "%s: %s", "compression: %s"`, key, value, s.Compression)
			}
		}
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *GRPCProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultGRPCProbe
	type plain GRPCProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultDNSProbe
	type plain DNSProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

func (s *DNSProbe) Validate() error {
	if s.QueryName == "" {
		return errors.New("query name must be set for DNS module")
	}
	if s.QueryClass != "" {
		if _, ok := dns.StringToClass[s.QueryClass]; !ok {
			return fmt.Errorf("query class '%s' is not valid", s.QueryClass)
		}
	}
	if s.QueryType != "" {
		if _, ok := dns.StringToType[s.QueryType]; !ok {
			return fmt.Errorf("query type '%s' is not valid", s.QueryType)
		}
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultTCPProbe
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
	*s = DefaultICMPProbe
	type plain ICMPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if err := s.Validate(); err != nil {
		return err
	}
	return nil
}

func (s *ICMPProbe) Validate() error {
	if runtime.GOOS == "windows" && s.DontFragment {
		return errors.New("\"dont_fragment\" is not supported on windows platforms")
	}

	if s.TTL < 0 {
		return errors.New("\"ttl\" cannot be negative")
	}
	if s.TTL > 255 {
		return errors.New("\"ttl\" cannot exceed 255")
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

	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

func (s *HeaderMatch) Validate() error {
	if s.Header == "" {
		return errors.New("header name must be set for HTTP header matchers")
	}

	if s.Regexp.Regexp == nil || s.Regexp.Regexp.String() == "" {
		return errors.New("regexp must be set for HTTP header matchers")
	}
	return nil
}

// isCompressionAcceptEncodingValid validates the compression +
// Accept-Encoding combination.
//
// If there's a compression setting, and there's also an accept-encoding
// header, they MUST match, otherwise we end up requesting something
// that doesn't include the specified compression, and that's likely to
// fail, depending on how the server is configured. Testing that the
// server _ignores_ Accept-Encoding, e.g. by not including a particular
// compression in the header but expecting it in the response falls out
// of the scope of the tests we perform.
//
// With that logic, this function validates that if a compression
// algorithm is specified, it's covered by the specified accept encoding
// header. It doesn't need to be the most prefered encoding, but it MUST
// be included in the prefered encodings.
func isCompressionAcceptEncodingValid(encoding, acceptEncoding string) bool {
	// unspecified compression + any encoding value is valid
	// any compression + no accept encoding is valid
	if encoding == "" || acceptEncoding == "" {
		return true
	}

	type encodingQuality struct {
		encoding string
		quality  float32
	}

	var encodings []encodingQuality

	for _, parts := range strings.Split(acceptEncoding, ",") {
		var e encodingQuality

		if idx := strings.LastIndexByte(parts, ';'); idx == -1 {
			e.encoding = strings.TrimSpace(parts)
			e.quality = 1.0
		} else {
			parseQuality := func(str string) float32 {
				q, err := strconv.ParseFloat(str, 32)
				if err != nil {
					return 0
				}
				return float32(math.Round(q*1000) / 1000)
			}

			e.encoding = strings.TrimSpace(parts[:idx])

			q := strings.TrimSpace(parts[idx+1:])
			q = strings.TrimPrefix(q, "q=")
			e.quality = parseQuality(q)
		}

		encodings = append(encodings, e)
	}

	sort.SliceStable(encodings, func(i, j int) bool {
		return encodings[j].quality < encodings[i].quality
	})

	for _, e := range encodings {
		if encoding == e.encoding || e.encoding == "*" {
			return e.quality > 0
		}
	}

	return false
}
