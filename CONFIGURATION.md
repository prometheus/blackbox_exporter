## Blackbox exporter configuration

### Module
```yml

  # The protocol over which the probe will take place
  [ prober: <prober_value> ]

  # How long the probe will wait before giving up
  [ timeout: <duration> ]

```

### HTTP
```yml

  # Accepted status codes for this probe
  [ valid_status_codes: [ <status_value> ... ] | default = 2xx ]

  # The HTTP method the probe will use
  [ method: <method_name> ]

  # The HTTP headers set for the probe
  headers:
    host:
    accept-language:
    content-type:
    ...

  # Whether or not the probe will follow any redirects
  no_follow_redirects: [ <boolean> ]

  # Probe fails if SSL is present
  fail_if_ssl: [ <boolean> ]

  # Probe fails if SSL is not present
  fail_if_not_ssl: [ <boolean> ]

  # Probe fails if response matches regexp
  fail_if_matches_regexp: [ <value> ... ]

  # Probe failes if response does not match regexp
  fail_if_not_matches_regexp: [ <value> ... ]

  # Configuration for TLS protocol of HTTP probe
  tls_config:
    # Disable target certificate validation.
    insecure_skip_verify: [ <boolean> ]

    # The CA cert to use for the targets.
  	ca_file: [ <name> ]

    # The client cert file for the targets.
  	cert_file: [ <name> ]

    # The client key file for the targets.
  	key_file: [ <name> ]

    # Used to verify the hostname for the targets.
  	server_name: [ <name> ]

  # The preferred IP protocol of the HTTP probe
  preferred_ip_protocol: [ <value> ]

  # The body of the HTTP request used in probe
  body: [ <value> ]

```

### TCP

```yml

# The preferred IP protocol of the TCP probe
preferred_ip_protocol: [ <value> ]

# The query sent in the TCP probe and the expected associated response
query_response: [ [ expect: <value>, send: <value> ] ]

# Whether or not TLS is used
tls: [ <boolean> ]

# Configuration for TLS protocol of TCP probe
tls_config:

  # Disable target certificate validation.
  insecure_skip_verify: [ <boolean> ]

  # The CA cert to use for the targets.
  ca_file: [ <name> ]

  # The client cert file for the targets.
  cert_file: [ <name> ]

  # The client key file for the targets.
  key_file: [ <name> ]

  # Used to verify the hostname for the targets.
  server_name: [ <name> ]

```

### DNS

```yml

# The preferred IP protocol of the DNS probe
preferred_ip_protocol: [ <value> ]

transport_protocol: [ <value> ]

query_name: [ <value> ]

query_type: [ <value> | default = "ANY" ]

valid_rcodes: [ <value> | default = "NOERROR" ]

validate_answer_rrs:

  [ fail_if_matches_regexp: [ <value> ... ] ]

  [ fail_if_not_matches_regexp: [ <value> ... ] ]

validate_authority_rrs:

  [ fail_if_matches_regexp: [ <value> ... ] ]

  [ fail_if_not_matches_regexp: [ <value> ... ] ]

validate_additional_rrs:

  [ fail_if_matches_regexp: [ <value> ... ] ]

  [ fail_if_not_matches_regexp: [ <value> ... ] ]

```

### ICMP

```yml

# The preferred IP protocol of the ICMP probe
preferred_ip_protocol: <value>

```
