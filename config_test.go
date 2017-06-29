package main

import "testing"

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
