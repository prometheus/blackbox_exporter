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

package prober

import (
	"context"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net/url"
	"strings"
)

func ProbeBTCRPC(ctx context.Context, target string, params url.Values, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	disableTls := true
	host := target
	if strings.HasPrefix(target, "http://") {
		host = strings.TrimLeft(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		host = strings.TrimLeft(target, "https://")
		disableTls = false
	} else {
	}

	rpcUser := params.Get("user")
	rpcPass := params.Get("pass")

	connCfg := &rpcclient.ConnConfig{
		Host:         host,
		User:         rpcUser,
		Pass:         rpcPass,
		HTTPPostMode: true,       // Bitcoin core only supports HTTP POST mode
		DisableTLS:   disableTls, // Bitcoin core does not provide TLS by default
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		level.Error(logger).Log("Error creating new BTC RPC client: " + err.Error())
	}
	defer client.Shutdown()

	switch params.Get("module") {
	case "btc_chain_info":
		var (
			blockNumberGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "probe_btcrpc_block_number",
				Help: "",
			}, []string{"target"})
		)
		registry.MustRegister(blockNumberGaugeVec)

		blockNumber, err := client.GetBlockCount()
		if err != nil {
			level.Error(logger).Log("Error fetching block count: " + err.Error())
			return
		}

		blockNumberGaugeVec.WithLabelValues(target).Set(float64(blockNumber))
	}

	return true
}
