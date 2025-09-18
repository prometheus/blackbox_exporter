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
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateChecksum(t *testing.T) {
	// Create a temporary file and establish the "original" state.
	// All subsequent tests will measure against this state.
	originalContent := []byte("modules:\n  http_2xx:\n    prober: http\n")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "config.yaml")

	if err := os.WriteFile(filePath, originalContent, 0644); err != nil {
		t.Fatalf("Could not write initial file: %v", err)
	}

	originalChecksum, err := GenerateChecksum(filePath)
	if err != nil {
		t.Fatalf("Could not generate initial checksum: %v", err)
	}
	if originalChecksum == "" {
		t.Fatal(" Initial checksum should not be empty")
	}

	t.Run("when content is appended", func(t *testing.T) {
		testModification(t, filePath, originalContent, originalChecksum, []byte("modules:\n  http_2xx:\n    prober: http\n  new_module:\n"))
	})

	t.Run("when content is completely replaced", func(t *testing.T) {
		testModification(t, filePath, originalContent, originalChecksum, []byte("completely: different\n"))
	})

	t.Run("when content is cleared (file becomes empty)", func(t *testing.T) {
		testModification(t, filePath, originalContent, originalChecksum, []byte(""))
	})

	// These tests do not fit the modify-restore pattern and are handled independently.
	t.Run("should return an error for a non-existent file", func(t *testing.T) {
		nonExistentPath := filepath.Join(tempDir, "this-file-does-not-exist.yaml")

		checksum, err := GenerateChecksum(nonExistentPath)

		if err == nil {
			t.Fatal("Expected an error for a non-existent file, but got nil")
		}
		if checksum != "" {
			t.Errorf("Checksum should be empty on error, but got: %s", checksum)
		}
	})

	t.Run("should return an error when path is a directory", func(t *testing.T) {
		checksum, err := GenerateChecksum(tempDir)

		if err == nil {
			t.Fatal("Expected an error when the path is a directory, but got nil")
		}
		if checksum != "" {
			t.Errorf("Checksum should be empty on error, but got: %s", checksum)
		}
	})
}

// testModification is a helper function that encapsulates the user's requested test logic:
// 1. Write new content.
// 2. Check that the checksum is different.
// 3. Write the original content back.
// 4. Check that the checksum is the same as the original.
func testModification(t *testing.T, filePath string, originalContent []byte, originalChecksum string, newContent []byte) {
	t.Helper()

	if err := os.WriteFile(filePath, newContent, 0644); err != nil {
		t.Fatalf("Failed to write new content to file: %v", err)
	}

	modifiedChecksum, err := GenerateChecksum(filePath)
	if err != nil {
		t.Fatalf("Failed to generate checksum for modified file: %v", err)
	}
	if modifiedChecksum == originalChecksum {
		t.Error("Checksum did not change after modifying file content")
	}
	if err := os.WriteFile(filePath, originalContent, 0644); err != nil {
		t.Fatalf("Failed to restore original content to file: %v", err)
	}

	restoredChecksum, err := GenerateChecksum(filePath)
	if err != nil {
		t.Fatalf("Failed to generate checksum for restored file: %v", err)
	}
	if restoredChecksum != originalChecksum {
		t.Errorf("Checksum should be restored to original value, but it was not.\nOriginal: %s\nRestored: %s", originalChecksum, restoredChecksum)
	}
}
