package ssl

import (
	"github.com/prometheus/client_golang/prometheus"
)

import (
	"github.com/prometheus/blackbox_exporter/internal/metrics/other"
)

// Contains SSL leaf certificate information
type ProbeLastChainInfo struct {
	*prometheus.GaugeVec
	extra ProbeLastChainInfoExtra
}

func NewProbeLastChainInfo() ProbeLastChainInfo {
	labels := []string{other.AttrFingerprintSha256("").Key(), other.AttrIssuer("").Key(), other.AttrSerialnumber("").Key(), other.AttrSubject("").Key(), other.AttrSubjectalternative("").Key()}
	return ProbeLastChainInfo{GaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_info",
		Help: "Contains SSL leaf certificate information",
	}, labels)}
}

func (m ProbeLastChainInfo) With(fingerprint_sha256 other.AttrFingerprintSha256, issuer other.AttrIssuer, serialnumber other.AttrSerialnumber, subject other.AttrSubject, subjectalternative other.AttrSubjectalternative, extras ...interface{}) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(string(fingerprint_sha256), string(issuer), string(serialnumber), string(subject), string(subjectalternative))
}

// Deprecated: Use [ProbeLastChainInfo.With] instead
func (m ProbeLastChainInfo) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GaugeVec.WithLabelValues(lvs...)
}

type ProbeLastChainInfoExtra struct {
}

/*
State {
    name: "metric.go.j2",
    current_block: None,
    auto_escape: None,
    ctx: {
        "AttrExtra": "ProbeLastChainInfoExtra",
        "Instr": "Gauge",
        "InstrMap": {
            "counter": "Counter",
            "gauge": "Gauge",
            "histogram": "Histogram",
            "updowncounter": "Gauge",
        },
        "Name": "probe.last.chain.info",
        "Type": "ProbeLastChainInfo",
        "attributes": [
            {
                "brief": "SHA256 fingerprint of the certificate",
                "examples": [
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ],
                "name": "fingerprint_sha256",
                "requirement_level": "required",
                "stability": "stable",
                "type": "string",
            },
            {
                "brief": "Issuer of the certificate",
                "examples": [
                    "CN=Example CA,O=Example Corp,C=US",
                ],
                "name": "issuer",
                "requirement_level": "required",
                "stability": "stable",
                "type": "string",
            },
            {
                "brief": "Serial number of the certificate",
                "examples": [
                    "1234567890abcdef",
                ],
                "name": "serialnumber",
                "requirement_level": "required",
                "stability": "stable",
                "type": "string",
            },
            {
                "brief": "Subject of the certificate",
                "examples": [
                    "CN=example.com,O=Example Corp,L=San Francisco,ST=CA,C=US",
                ],
                "name": "subject",
                "requirement_level": "required",
                "stability": "stable",
                "type": "string",
            },
            {
                "brief": "Subject alternative names of the certificate",
                "examples": [
                    "DNS:example.com,DNS:www.example.com",
                ],
                "name": "subjectalternative",
                "requirement_level": "required",
                "stability": "stable",
                "type": "string",
            },
        ],
        "ctx": {
            "attributes": [
                {
                    "brief": "SHA256 fingerprint of the certificate",
                    "examples": [
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    ],
                    "name": "fingerprint_sha256",
                    "requirement_level": "required",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Subject of the certificate",
                    "examples": [
                        "CN=example.com,O=Example Corp,L=San Francisco,ST=CA,C=US",
                    ],
                    "name": "subject",
                    "requirement_level": "required",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Issuer of the certificate",
                    "examples": [
                        "CN=Example CA,O=Example Corp,C=US",
                    ],
                    "name": "issuer",
                    "requirement_level": "required",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Subject alternative names of the certificate",
                    "examples": [
                        "DNS:example.com,DNS:www.example.com",
                    ],
                    "name": "subjectalternative",
                    "requirement_level": "required",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Serial number of the certificate",
                    "examples": [
                        "1234567890abcdef",
                    ],
                    "name": "serialnumber",
                    "requirement_level": "required",
                    "stability": "stable",
                    "type": "string",
                },
            ],
            "brief": "Contains SSL leaf certificate information",
            "events": [],
            "id": "metric.ssl.probe.last.chain.info",
            "instrument": "gauge",
            "lineage": {
                "attributes": {
                    "fingerprint_sha256": {
                        "inherited_fields": [
                            "brief",
                            "examples",
                            "note",
                            "stability",
                        ],
                        "locally_overridden_fields": [
                            "requirement_level",
                        ],
                        "source_group": "registry.tls",
                    },
                    "issuer": {
                        "inherited_fields": [
                            "brief",
                            "examples",
                            "note",
                            "stability",
                        ],
                        "locally_overridden_fields": [
                            "requirement_level",
                        ],
                        "source_group": "registry.tls",
                    },
                    "serialnumber": {
                        "inherited_fields": [
                            "brief",
                            "examples",
                            "note",
                            "stability",
                        ],
                        "locally_overridden_fields": [
                            "requirement_level",
                        ],
                        "source_group": "registry.tls",
                    },
                    "subject": {
                        "inherited_fields": [
                            "brief",
                            "examples",
                            "note",
                            "stability",
                        ],
                        "locally_overridden_fields": [
                            "requirement_level",
                        ],
                        "source_group": "registry.tls",
                    },
                    "subjectalternative": {
                        "inherited_fields": [
                            "brief",
                            "examples",
                            "note",
                            "stability",
                        ],
                        "locally_overridden_fields": [
                            "requirement_level",
                        ],
                        "source_group": "registry.tls",
                    },
                },
                "provenance": {
                    "path": "../../semconv/tls/metrics.yaml",
                    "registry_id": "main",
                },
            },
            "metric_name": "probe_ssl_last_chain_info",
            "name": none,
            "root_namespace": "ssl",
            "span_kind": none,
            "stability": "stable",
            "type": "metric",
            "unit": "1",
        },
        "for_each_attr": <macro for_each_attr>,
        "module": "github.com/prometheus/blackbox_exporter/internal/metrics",
    },
    env: Environment {
        globals: {
            "concat_if": weaver_forge::extensions::util::concat_if,
            "cycler": minijinja_contrib::globals::cycler,
            "debug": minijinja::functions::builtins::debug,
            "dict": minijinja::functions::builtins::dict,
            "joiner": minijinja_contrib::globals::joiner,
            "namespace": minijinja::functions::builtins::namespace,
            "params": {
                "module": "github.com/prometheus/blackbox_exporter/internal/metrics",
                "params": {
                    "module": "github.com/prometheus/blackbox_exporter/internal/metrics",
                },
            },
            "range": minijinja::functions::builtins::range,
            "template": {},
        },
        tests: [
            "!=",
            "<",
            "<=",
            "==",
            ">",
            ">=",
            "array",
            "boolean",
            "defined",
            "deprecated",
            "divisibleby",
            "endingwith",
            "enum",
            "enum_type",
            "eq",
            "equalto",
            "escaped",
            "even",
            "experimental",
            "false",
            "filter",
            "float",
            "ge",
            "greaterthan",
            "gt",
            "in",
            "int",
            "integer",
            "iterable",
            "le",
            "lessthan",
            "lower",
            "lt",
            "mapping",
            "ne",
            "none",
            "number",
            "odd",
            "safe",
            "sameas",
            "sequence",
            "simple_type",
            "stable",
            "startingwith",
            "string",
            "template_type",
            "test",
            "true",
            "undefined",
            "upper",
        ],
        filters: [
            "abs",
            "acronym",
            "ansi_bg_black",
            "ansi_bg_blue",
            "ansi_bg_bright_black",
            "ansi_bg_bright_blue",
            "ansi_bg_bright_cyan",
            "ansi_bg_bright_green",
            "ansi_bg_bright_magenta",
            "ansi_bg_bright_red",
            "ansi_bg_bright_white",
            "ansi_bg_bright_yellow",
            "ansi_bg_cyan",
            "ansi_bg_green",
            "ansi_bg_magenta",
            "ansi_bg_red",
            "ansi_bg_white",
            "ansi_bg_yellow",
            "ansi_black",
            "ansi_blue",
            "ansi_bold",
            "ansi_bright_black",
            "ansi_bright_blue",
            "ansi_bright_cyan",
            "ansi_bright_green",
            "ansi_bright_magenta",
            "ansi_bright_red",
            "ansi_bright_white",
            "ansi_bright_yellow",
            "ansi_cyan",
            "ansi_green",
            "ansi_italic",
            "ansi_magenta",
            "ansi_red",
            "ansi_strikethrough",
            "ansi_underline",
            "ansi_white",
            "ansi_yellow",
            "attr",
            "attribute_id",
            "attribute_namespace",
            "attribute_registry_file",
            "attribute_registry_namespace",
            "attribute_registry_title",
            "attribute_sort",
            "batch",
            "body_fields",
            "bool",
            "camel_case",
            "camel_case_const",
            "capitalize",
            "capitalize_first",
            "comment",
            "comment_with_prefix",
            "count",
            "d",
            "default",
            "dictsort",
            "e",
            "enum_type",
            "escape",
            "filesizeformat",
            "first",
            "flatten",
            "float",
            "groupby",
            "indent",
            "instantiated_type",
            "int",
            "items",
            "join",
            "kebab_case",
            "kebab_case_const",
            "last",
            "length",
            "lines",
            "list",
            "lower",
            "lower_case",
            "map",
            "map_text",
            "markdown_to_html",
            "max",
            "metric_namespace",
            "min",
            "not_required",
            "pascal_case",
            "pascal_case_const",
            "pluralize",
            "pprint",
            "print_member_value",
            "regex_replace",
            "reject",
            "rejectattr",
            "replace",
            "required",
            "reverse",
            "round",
            "safe",
            "screaming_kebab_case",
            "screaming_snake_case",
            "screaming_snake_case_const",
            "select",
            "selectattr",
            "slice",
            "snake_case",
            "snake_case_const",
            "sort",
            "split",
            "split_id",
            "string",
            "striptags",
            "sum",
            "title",
            "title_case",
            "tojson",
            "toyaml",
            "trim",
            "truncate",
            "type_mapping",
            "unique",
            "upper",
            "upper_case",
            "urlencode",
        ],
        templates: [
            "metric.go.j2",
        ],
    },
}
*/
