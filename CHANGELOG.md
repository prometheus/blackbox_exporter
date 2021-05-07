## 0.19.0 / 2021-05-07

This release is built with go 1.16.4, which contains a [bugfix](https://github.com/golang/go/issues/45712)
that can cause an untrusted target to make Blackbox Exporter crash.

* [FEATURE] Add support for decompression of HTTP responses. #764
* [FEATURE] Enable TLS and basic authentication. #784
* [FEATURE] HTTP probe: *experimental* OAuth2 support.
* [ENHANCEMENT] Add a health endpoint. #752
* [ENHANCEMENT] Add a metric for unknown probes. #716
* [ENHANCEMENT] Use preferred protocol first when resolving hostname. #728
* [ENHANCEMENT] Validating the configuration tries to compile regexes. #729
* [BUGFIX] HTTP probe: Fix error checking. #723
* [BUGFIX] HTTP probe: Fix how the tls phase is calculated. #758
