package main

import (
	"github.com/prometheus/common/log"
	"io/ioutil"
	"net/http"
)

func probePROXY(target string, w http.ResponseWriter, module Module) bool {

	if len(module.Proxy.ValidTargets) > 0 {
		allowed := false
		for _, validTarget := range module.Proxy.ValidTargets {
			if target == validTarget {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Errorf("Target '%s' not part of valid targets: %+v", target, module.Proxy.ValidTargets)
			return false
		}
	}

	client := &http.Client{
		Timeout: module.Timeout,
	}

	tlsconfig, err := module.Proxy.TLSConfig.GenerateConfig()
	if err != nil {
		log.Errorf("Error generating TLS config: %s", err)
		return false
	}

	client.Transport = &http.Transport{
		TLSClientConfig:   tlsconfig,
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
	}

	request, err := http.NewRequest("GET", target, nil)
	if err != nil {
		log.Errorf("Error creating request for target %s: %s", target, err)
		return false
	}

	resp, err := client.Do(request)
	if err != nil {
		log.Warnf("Error sending HTTP request to %s: %s", target, err)
		return false
	}

	if resp.StatusCode != 200 {
		log.Warnf("Error invalid status code %d, expected 200", resp.StatusCode)
		return false
	}

	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warnf("Error for Proxy body read from %s: %s", target, err)
		return false
	}

	bytes = append(bytes, []byte("\n")...)
	_, err = w.Write(bytes)
	if err != nil {
		log.Warnf("Error for Proxy body write from %s: %s", target, err)
		return false
	}

	return true
}
