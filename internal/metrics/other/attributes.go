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
