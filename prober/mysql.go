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
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	_ "github.com/go-sql-driver/mysql"
	"github.com/prometheus/blackbox_exporter/config"
)

func ProbeMYSQL(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {

	mysqlConfig := module.MYSQL
	mysqlDsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql", mysqlConfig.Username, mysqlConfig.Password, target, mysqlConfig.Port)

	// level.Error(logger).Log("msg", "Debug: ", "err", mysqlDsn)

	db, err := sql.Open("mysql", mysqlDsn)
	if err != nil {
		logger.Error("Unable to connect", "err", err)
		return false
	}
	defer db.Close()

	db.SetConnMaxLifetime(time.Minute * 2)
	db.SetMaxOpenConns(1)

	err = db.Ping()
	if err != nil {
		logger.Error("Unable to connect", "err", err)
		return false
	}

	rows, err := db.Query(mysqlConfig.Query)
	if err != nil {
		logger.Error("Query failed", "err", err)
		return false
	}
	defer rows.Close()

	// Parse results
	cols, _ := rows.Columns()

	dest := make([]interface{}, 0, len(cols))
	for range cols {
		dest = append(dest, new(string))
	}

	rows.Next()
	rows.Scan(dest...)

	result := make(map[string]string, len(cols))
	for i, column_name := range cols {
		result[column_name] = *dest[i].(*string)
	}

	// Check the expected result
	for _, expectedRow := range mysqlConfig.SqlQueryResponse {
		if result[expectedRow.Column] != expectedRow.Value {
			logger.Error("Expected:", "err", expectedRow.Value)
			logger.Error("Current:", "err", result[expectedRow.Column])
			return false
		}
	}

	db.Close()

	return true
}
