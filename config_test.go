package main

import (
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

func TestLoadConfig(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.reloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "blackbox.yml", err)
	}
}

func TestLoadBadConfig(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	expected := "unknown fields in dns probe: invalid_extra_field"

	err := sc.reloadConfig("testdata/blackbox-bad.yml")
	if err.Error() != expected {
		t.Errorf("\nexpected:\n%v\ngot:\n%v", expected, err.Error())
	}
}

func TestHideConfigSecrets(t *testing.T) {

	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.reloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/blackbox-good.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshalling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}
