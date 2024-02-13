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
	"encoding/hex"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"math/big"
	"net/url"
	"strconv"
	"strings"
)

type ValidCallParam struct {
	ContractName    string
	ContractAddress string
	MethodName      string
	MethodArgs      string
}

func ProbeETHRPC(ctx context.Context, target string, params url.Values, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	eth, err := ethclient.Dial(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing rpc", target, err)
	}
	chainId, err := eth.ChainID(ctx)
	switch params.Get("module") {
	case "chain_info":
		var (
			gasPriceGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "probe_ethrpc_gas_price",
				Help: "",
			}, []string{"rpc", "chainId"})
			blockNumberGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "probe_ethrpc_gas_price",
				Help: "",
			}, []string{"rpc", "chainId"})
		)
		registry.MustRegister(gasPriceGaugeVec)
		registry.MustRegister(blockNumberGaugeVec)
	case "balance":
		var (
			balanceGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "probe_ethrpc_balance",
				Help: "",
			}, []string{"rpc", "chainId", "accountAddress", "accountName"})
		)
		registry.MustRegister(balanceGaugeVec)
	case "erc20balance":
		var (
			erc20balanceGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "probe_ethrpc_erc20balance",
				Help: "",
			}, []string{"rpc", "chainId", "accountAddress", "accountName", "tokenSymbol", "tokenAddress"})
		)
		registry.MustRegister(erc20balanceGaugeVec)
	case "contract_call":
		var (
			contractCallGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "probe_ethrpc_contract_call",
				Help: "",
			}, []string{"rpc", "chainId", "contractAddress", "contractName", "methodName", "methodArgs"})
		)
		registry.MustRegister(contractCallGaugeVec)
		callParams := params["call"]
		if len(callParams) <= 0 {
			level.Error(logger).Log("msg", "no call args for module")
			return false
		}
		var batch []rpc.BatchElem
		var validCallParams []ValidCallParam
		var methodName string
		var outputType string

		for _, callParam := range callParams {
			p := strings.Split(callParam, "|")
			if len(p) < 3 {
				level.Error(logger).Log("msg", "Need to config at least ContractName|ContractAddress|AbiJson", "callParam", callParam)
				continue
			}
			contractName := p[0]
			//contractAddress := common.HexToAddress(p[1])
			contractAddress := p[1]
			abiJson := p[2]
			contractArgsString := ""
			var contractArgs []interface{}

			abiObj, err := abi.JSON(strings.NewReader(abiJson))

			if err != nil {
				level.Error(logger).Log("msg", "Abi json decode failed, "+err.Error(), "callParam", callParam)
				continue
			}

			if len(abiObj.Methods) != 1 {
				level.Error(logger).Log("msg", "Only support one method, ", "callParam", callParam)
				break
			}

			for n, def := range abiObj.Methods {
				methodName = n

				if len(def.Outputs) != 1 {
					level.Error(logger).Log("msg", "Only support one method output, ", "callParam", callParam)
					break
				}

				outputType = def.Outputs[0].Type.String()

				if len(p) < 4 {
					break
				}

				contractArgsString = p[3]
				contractArgsStringArr := strings.Split(p[3], ",")

				for i, arg := range def.Inputs {
					inputArg := contractArgsStringArr[i]
					typeString := arg.Type.String()
					if arg.Type.String() == "address" {
						contractArgs = append(contractArgs, common.HexToAddress(inputArg))
					} else if strings.Contains(typeString, "int") {
						n, _ := strconv.ParseInt(inputArg, 10, 64)
						switch typeString {
						case "int8":
							contractArgs = append(contractArgs, int8(n))
						case "int16":
							contractArgs = append(contractArgs, int16(n))
						case "int32":
							contractArgs = append(contractArgs, int32(n))
						case "int64":
							contractArgs = append(contractArgs, int64(n))
						case "uint8":
							contractArgs = append(contractArgs, uint8(n))
						case "uint16":
							contractArgs = append(contractArgs, uint16(n))
						case "uint32":
							contractArgs = append(contractArgs, uint32(n))
						case "uint64":
							contractArgs = append(contractArgs, uint64(n))
						default:
							contractArgs = append(contractArgs, big.NewInt(n))
						}
					} else if typeString == "bool" {
						r, err := strconv.ParseBool(inputArg)
						if err != nil {
							level.Error(logger).Log("msg", "not a bool value"+err.Error(), "arg", inputArg)
						}
						contractArgs = append(contractArgs, r)
					} else {
						contractArgs = append(contractArgs, inputArg)
					}
				}
				break
			}

			callData, err := abiObj.Pack(methodName, contractArgs...)

			if err != nil {
				level.Error(logger).Log("msg", "abi pack failed, "+err.Error(), "callParam", callParam)
				continue
			}

			//callMsg := ethereum.CallMsg{To: &contractAddress, Data: hex.EncodeToString(callData), Gas: 0}
			callMsg := struct {
				To   string `json:"to"`
				Data string `json:"data"`
			}{
				To:   contractAddress,
				Data: "0x" + hex.EncodeToString(callData),
			}
			var result string
			batch = append(batch, rpc.BatchElem{
				Method: "eth_call",
				Args:   []interface{}{callMsg, "latest"},
				Result: &result,
				Error:  nil,
			})

			validCallParams = append(validCallParams, ValidCallParam{
				ContractName:    contractName,
				ContractAddress: contractAddress,
				MethodName:      methodName,
				MethodArgs:      contractArgsString,
			})

		}
		err = eth.Client().BatchCall(batch)
		if err != nil {
			level.Error(logger).Log("msg", "batchcall failed, "+err.Error())
			return false
		}
		for i, e := range batch {
			r := *e.Result.(*string)
			level.Info(logger).Log("msg", "result "+r)
			r = strings.ReplaceAll(r, "0x", "")
			var value float64
			if outputType == "uint256" || outputType == "int256" {
				n := new(big.Int)
				n.SetString(r, 16)
				value, _ = weiToEther(n).Float64()
			} else {
				valueInt, err := strconv.ParseInt(r, 16, 64)
				if err != nil {
					level.Error(logger).Log("msg", "ParseInt failed, "+err.Error(), "HexValue", r)
				}
				value = float64(valueInt)
			}
			contractCallGaugeVec.WithLabelValues(
				target,
				strconv.FormatInt(chainId.Int64(), 10),
				validCallParams[i].ContractAddress,
				validCallParams[i].ContractName,
				validCallParams[i].MethodName,
				validCallParams[i].MethodArgs,
			).Set(value)
		}
	}

	return true
}

func weiToEther(wei *big.Int) *big.Float {
	f := new(big.Float)
	f.SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	f.SetMode(big.ToNearestEven)
	fWei := new(big.Float)
	fWei.SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	fWei.SetMode(big.ToNearestEven)
	return f.Quo(fWei.SetInt(wei), big.NewFloat(params.Ether))
}
