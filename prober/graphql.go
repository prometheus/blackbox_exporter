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
	"encoding/json"
	"fmt"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jmespath/go-jmespath"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	ContentTypeApplicationJson = "application/json"
)

func ProbeGraphQL(ctx context.Context, target string, params url.Values, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	var (
		graphqlGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_graphql_query",
			Help: "",
		}, []string{"target", "jmespath"})
	)
	registry.MustRegister(graphqlGaugeVec)

	var hc = &http.Client{Timeout: 10 * time.Second}

	for _, q := range params["query"] {

		qarr := strings.Split(q, "|")

		if len(qarr) != 2 {
			level.Error(logger).Log("msg", "query params format is invalid, SKIP! valid format: graphql|jmespath")
			continue
		}

		reqBody := fmt.Sprintf("{\"query\": \"%s\"}", qarr[0])
		jmespathString := qarr[1]

		resp, err := hc.Post(target, ContentTypeApplicationJson, strings.NewReader(reqBody))

		if err != nil {
			level.Error(logger).Log("msg", "Error occurs when request "+err.Error())
			return false
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)

		if err != nil {
			level.Error(logger).Log("msg", "Error occurs when read body "+err.Error())
			return false
		}

		var data interface{}

		err = json.Unmarshal(body, &data)

		if err != nil {
			level.Error(logger).Log("msg", "Error occurs when unmarshal json body "+err.Error())
			return false
		}

		result, err := jmespath.Search(jmespathString, data)
		if err != nil {
			level.Error(logger).Log("msg", "Error jmespath search "+err.Error(), "jsondata", data)
			return false
		}
		var value float64
		resultType := reflect.TypeOf(result).String()
		if strings.Contains(resultType, "float") || strings.Contains(resultType, "int") {
			value = result.(float64)
		} else if strings.Contains(resultType, "string") {
			value, err = strconv.ParseFloat(result.(string), 64)
		} else {
			level.Error(logger).Log("msg", "Make sure the value get from jmespath is not a number "+result.(string))
			return false
		}
		graphqlGaugeVec.WithLabelValues(target, jmespathString).Set(value)
	}
	return true
}
