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
