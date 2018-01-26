# Blackbox exporter configuration

The file is written in [YAML format](http://en.wikipedia.org/wiki/YAML), defined by the scheme described below.
Brackets indicate that a parameter is optional.
For non-list parameters the value is set to the specified default.

Generic placeholders are defined as follows:

* `<boolean>`: a boolean that can take the values `true` or `false`
* `<int>`: a regular integer
* `<duration>`: a duration matching the regular expression `[0-9]+(ms|[smhdwy])`
* `<filename>`: a valid path in the current working directory
* `<string>`: a regular string
* `<secret>`: a regular string that is a secret, such as a password
* `<regex>`: a regular expression

The other placeholders are specified separately.

### Module
```yml

  # The protocol over which the probe will take place (http, tcp, dns, icmp).
  prober: <prober_string>

  # How long the probe will wait before giving up.
  [ timeout: <duration> ]

  # The specific probe configuration - at most one of these should be specified.
  [ http: <http_probe> ]
  [ tcp: <tcp_probe> ]
  [ dns: <dns_probe> ]
  [ icmp: <icmp_probe> ]

```

### <http_probe>
```yml

  # Accepted status codes for this probe. Defaults to 2xx.
  [ valid_status_codes: <int>, ... | default = 2xx ]

  # Accepted HTTP versions for this probe.
  [ valid_http_versions: <string>, ... ]

  # The HTTP method the probe will use.
  [ method: <string> | default = "GET" ]

  # The HTTP headers set for the probe.
  headers:
    [ <string>: <string> ... ]

  # Whether or not the probe will follow any redirects.
  [ no_follow_redirects: <boolean> | default = false ]

  # Probe fails if SSL is present.
  [ fail_if_ssl: <boolean> | default = false ]

  # Probe fails if SSL is not present.
  [ fail_if_not_ssl: <boolean> | default = false ]

  # Probe fails if response matches regex.
  fail_if_matches_regexp:
    [ - <regex>, ... ]

  # Probe fails if response does not match regex.
  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

  # Configuration for TLS protocol of HTTP probe.
  tls_config:
    [ <tls_config> ]

  # The HTTP basic authentication credentials for the targets.
  basic_auth:
    [ username: <string> ]
    [ password: <secret> ]

  # The bearer token for the targets.
  [ bearer_token: <secret> ]

  # The bearer token file for the targets.
  [ bearer_token_file: <filename> ]

  # HTTP proxy server to use to connect to the targets.
  [ proxy_url: <string> ]

  # The preferred IP protocol of the HTTP probe (ip4, ip6).
  [ preferred_ip_protocol: <string> | default = "ip6" ]

  # The body of the HTTP request used in probe.
  body: [ <string> ]


```

### <tcp_probe>

```yml

# The preferred IP protocol of the TCP probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]

# The source IP address.
[ source_ip_address: <string> ]

# The query sent in the TCP probe and the expected associated response.
# starttls upgrades TCP connection to TLS.
query_response:
  [ - [ [ expect: <string> ],
        [ send: <string> ],
        [ starttls: <boolean | default = false> ]
      ], ...
  ]

# Whether or not TLS is used when the connection is initiated.
[ tls: <boolean | default = false> ]

# Configuration for TLS protocol of TCP probe.
tls_config:
  [ <tls_config> ]

```

### <dns_probe>

```yml

# The preferred IP protocol of the DNS probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]

# The source IP address.
[ source_ip_address: <string> ]

[ transport_protocol: <string> | default = "udp" ] # udp, tcp

query_name: <string>

[ query_type: <string> | default = "ANY" ]

# List of valid response codes.
valid_rcodes:
  [ - <string> ... | default = "NOERROR" ]

validate_answer_rrs:

  fail_if_matches_regexp:
    [ - <regex>, ... ]

  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

validate_authority_rrs:

  fail_if_matches_regexp:
    [ - <regex>, ... ]

  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

validate_additional_rrs:

  fail_if_matches_regexp:
    [ - <regex>, ... ]

  fail_if_not_matches_regexp:
    [ - <regex>, ... ]

```

### <icmp_probe>

```yml

# The preferred IP protocol of the ICMP probe (ip4, ip6).
[ preferred_ip_protocol: <string> | default = "ip6" ]

# The source IP address.
[ source_ip_address: <string> ]

# Set the DF-bit in the IP-header. Only works with ip4 and on *nix systems.
[ dont_fragment: <boolean> | default = false ]

# The size of the payload.
[ payload_size: <int> ]

```

### <tls_config>

```yml

# Disable target certificate validation.
[ insecure_skip_verify: <boolean> | default = false ]

# The CA cert to use for the targets.
[ ca_file: <filename> ]

# The client cert file for the targets.
[ cert_file: <filename> ]

# The client key file for the targets.
[ key_file: <filename> ]

# Used to verify the hostname for the targets.
[ server_name: <string> ]

```
