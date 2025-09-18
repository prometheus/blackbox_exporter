// Copyright 2025 The Prometheus Authors
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
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func GenerateChecksum(yamlFilePath string) (string, error) {
	hash := sha256.New()
	yamlContent, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return "", fmt.Errorf("error reading YAML file: %w", err)
	}
	_, err = hash.Write(yamlContent)
	if err != nil {
		return "", fmt.Errorf("error writing YAML file to hash: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
