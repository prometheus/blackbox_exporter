## 0.19.0 / 2021-05-10

In the HTTP probe, `no_follow_redirects` has been changed to `follow_redirects`.
This release accepts both, with a precedence to the `no_follow_redirects` parameter.
In the next release, `no_follow_redirects` will be removed.

* [CHANGE] HTTP probe: `no_follow_redirects` has been renamed to `follow_redirects`. #784
* [FEATURE] Add support for decompression of HTTP responses. #764
* [FEATURE] Enable TLS and basic authentication. #730
* [FEATURE] HTTP probe: *experimental* OAuth2 support. #784
* [ENHANCEMENT] Add a health endpoint. #752
* [ENHANCEMENT] Add a metric for unknown probes. #716
* [ENHANCEMENT] Use preferred protocol first when resolving hostname. #728
* [ENHANCEMENT] Validating the configuration tries to compile regexes. #729
* [BUGFIX] HTTP probe: Fix error checking. #723
* [BUGFIX] HTTP probe: Fix how the TLS phase is calculated. #758
