package probers

import (
  "net/http"
  "fmt"
)

func init() {
  Probers["http"] = probeHTTP
}

type HTTPProbe struct {
  // Defaults to 2xx.
  ValidStatusCodes []int `yaml:"valid_status_codes"`
  FollowRedirects bool `yaml:"follow_redirects"`
  FailIfSSL bool `yaml:"fail_if_ssl"`
  FailIfNotSSL bool `yaml:"fail_if_not_ssl"`
}

func probeHTTP(target string, w http.ResponseWriter) (success bool) {
	var isSSL int
	resp, err := http.Get(target)
	if err == nil {
		if 200 >= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		}
		defer resp.Body.Close()
	}
	if resp.TLS != nil {
		isSSL = 1
	}
	fmt.Fprintf(w, "probe_http_status_code %d\n", resp.StatusCode)
	fmt.Fprintf(w, "probe_http_content_length %d\n", resp.ContentLength)
	fmt.Fprintf(w, "probe_http_ssl %d\n", isSSL)
	return
}
