package other

// TLS cipher suite
type AttrCipher string // cipher

func (AttrCipher) Stable()         {}
func (AttrCipher) Recommended()    {}
func (AttrCipher) Key() string     { return "cipher" }
func (a AttrCipher) Value() string { return string(a) }

// SHA256 fingerprint of the certificate
type AttrFingerprintSha256 string // fingerprint_sha256

func (AttrFingerprintSha256) Stable()         {}
func (AttrFingerprintSha256) Recommended()    {}
func (AttrFingerprintSha256) Key() string     { return "fingerprint_sha256" }
func (a AttrFingerprintSha256) Value() string { return string(a) }

// Hop limit (TTL for IPv4) of the replied packet
type AttrHopLimit string // hop_limit

func (AttrHopLimit) Stable()         {}
func (AttrHopLimit) Recommended()    {}
func (AttrHopLimit) Key() string     { return "hop_limit" }
func (a AttrHopLimit) Value() string { return string(a) }

// Issuer of the certificate
type AttrIssuer string // issuer

func (AttrIssuer) Stable()         {}
func (AttrIssuer) Recommended()    {}
func (AttrIssuer) Key() string     { return "issuer" }
func (a AttrIssuer) Value() string { return string(a) }

// Probe phase
type AttrPhase string // phase

func (AttrPhase) Stable()         {}
func (AttrPhase) Recommended()    {}
func (AttrPhase) Key() string     { return "phase" }
func (a AttrPhase) Value() string { return string(a) }

const PhaseResolve AttrPhase = "resolve"
const PhaseConnect AttrPhase = "connect"
const PhaseRequest AttrPhase = "request"
const PhaseTLS AttrPhase = "tls"
const PhaseProcessing AttrPhase = "processing"
const PhaseTransfer AttrPhase = "transfer"
const PhaseSetup AttrPhase = "setup"
const PhaseRTT AttrPhase = "rtt"
const PhaseCheck AttrPhase = "check"

// Serial number of the certificate
type AttrSerialnumber string // serialnumber

func (AttrSerialnumber) Stable()         {}
func (AttrSerialnumber) Recommended()    {}
func (AttrSerialnumber) Key() string     { return "serialnumber" }
func (a AttrSerialnumber) Value() string { return string(a) }

// gRPC health check serving status
type AttrServingStatus string // serving_status

func (AttrServingStatus) Stable()         {}
func (AttrServingStatus) Recommended()    {}
func (AttrServingStatus) Key() string     { return "serving_status" }
func (a AttrServingStatus) Value() string { return string(a) }

const ServingStatusServing AttrServingStatus = "SERVING"
const ServingStatusNotServing AttrServingStatus = "NOT_SERVING"
const ServingStatusUnknown AttrServingStatus = "UNKNOWN"
const ServingStatusServiceUnknown AttrServingStatus = "SERVICE_UNKNOWN"

// gRPC status code
type AttrStatusCode string // status_code

func (AttrStatusCode) Stable()         {}
func (AttrStatusCode) Recommended()    {}
func (AttrStatusCode) Key() string     { return "status_code" }
func (a AttrStatusCode) Value() string { return string(a) }

// Subject of the certificate
type AttrSubject string // subject

func (AttrSubject) Stable()         {}
func (AttrSubject) Recommended()    {}
func (AttrSubject) Key() string     { return "subject" }
func (a AttrSubject) Value() string { return string(a) }

// Subject alternative names of the certificate
type AttrSubjectalternative string // subjectalternative

func (AttrSubjectalternative) Stable()         {}
func (AttrSubjectalternative) Recommended()    {}
func (AttrSubjectalternative) Key() string     { return "subjectalternative" }
func (a AttrSubjectalternative) Value() string { return string(a) }

// TLS version
type AttrVersion string // version

func (AttrVersion) Stable()         {}
func (AttrVersion) Recommended()    {}
func (AttrVersion) Key() string     { return "version" }
func (a AttrVersion) Value() string { return string(a) }

/* State {
    name: "attr.go.j2",
    current_block: None,
    auto_escape: None,
    ctx: {
        "ctx": {
            "attributes": [
                {
                    "brief": "TLS cipher suite",
                    "examples": [
                        "TLS_AES_256_GCM_SHA384",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                    ],
                    "name": "cipher",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "SHA256 fingerprint of the certificate",
                    "examples": [
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    ],
                    "name": "fingerprint_sha256",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Hop limit (TTL for IPv4) of the replied packet",
                    "examples": [
                        64,
                        128,
                        255,
                    ],
                    "name": "hop_limit",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "int",
                },
                {
                    "brief": "Issuer of the certificate",
                    "examples": [
                        "CN=Example CA,O=Example Corp,C=US",
                    ],
                    "name": "issuer",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Probe phase",
                    "name": "phase",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": {
                        "members": [
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "resolve",
                                "note": none,
                                "stability": "stable",
                                "value": "resolve",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "connect",
                                "note": none,
                                "stability": "stable",
                                "value": "connect",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "request",
                                "note": none,
                                "stability": "stable",
                                "value": "request",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "tls",
                                "note": none,
                                "stability": "stable",
                                "value": "tls",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "processing",
                                "note": none,
                                "stability": "stable",
                                "value": "processing",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "transfer",
                                "note": none,
                                "stability": "stable",
                                "value": "transfer",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "setup",
                                "note": none,
                                "stability": "stable",
                                "value": "setup",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "rtt",
                                "note": none,
                                "stability": "stable",
                                "value": "rtt",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "check",
                                "note": none,
                                "stability": "stable",
                                "value": "check",
                            },
                        ],
                    },
                },
                {
                    "brief": "Serial number of the certificate",
                    "examples": [
                        "1234567890abcdef",
                    ],
                    "name": "serialnumber",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "gRPC health check serving status",
                    "name": "serving_status",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": {
                        "members": [
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "serving",
                                "note": none,
                                "stability": "stable",
                                "value": "SERVING",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "not_serving",
                                "note": none,
                                "stability": "stable",
                                "value": "NOT_SERVING",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "unknown",
                                "note": none,
                                "stability": "stable",
                                "value": "UNKNOWN",
                            },
                            {
                                "brief": none,
                                "deprecated": none,
                                "id": "service_unknown",
                                "note": none,
                                "stability": "stable",
                                "value": "SERVICE_UNKNOWN",
                            },
                        ],
                    },
                },
                {
                    "brief": "gRPC status code",
                    "examples": [
                        0,
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        9,
                        10,
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                    ],
                    "name": "status_code",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "int",
                },
                {
                    "brief": "Subject of the certificate",
                    "examples": [
                        "CN=example.com,O=Example Corp,L=San Francisco,ST=CA,C=US",
                    ],
                    "name": "subject",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "Subject alternative names of the certificate",
                    "examples": [
                        "DNS:example.com,DNS:www.example.com",
                    ],
                    "name": "subjectalternative",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
                {
                    "brief": "TLS version",
                    "examples": [
                        "TLS 1.3",
                        "TLS 1.2",
                    ],
                    "name": "version",
                    "requirement_level": "recommended",
                    "root_namespace": "other",
                    "stability": "stable",
                    "type": "string",
                },
            ],
            "root_namespace": "other",
        },
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
            "attr.go.j2",
        ],
    },
} */
