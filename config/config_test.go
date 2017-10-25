package config

import (
	"strings"
	"testing"

	"github.com/go-kit/kit/log"
	"gopkg.in/yaml.v2"
  "github.com/prometheus/common/config"
)

func TestLoadConfig(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.ReloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "blackbox.yml", err)
	}
}

func TestLoadBadConfigs(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}
	tests := []struct {
		ConfigFile    string
		ExpectedError string
	}{
		{
			ConfigFile:    "testdata/blackbox-bad.yml",
			ExpectedError: "Error parsing config file: unknown fields in dns probe: invalid_extra_field",
		},
		{
			ConfigFile:    "testdata/invalid-dns-module.yml",
			ExpectedError: "Error parsing config file: Query name must be set for DNS module",
		},
	}
	for i, test := range tests {
		err := sc.ReloadConfig(test.ConfigFile)
		if err.Error() != test.ExpectedError {
			t.Errorf("In case %v:\nExpected:\n%v\nGot:\n%v", i, test.ExpectedError, err.Error())
		}
	}
}

func TestHideConfigSecrets(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.ReloadConfig("testdata/blackbox-good.yml")
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

func TestCombineModulesWithString(t *testing.T) {
	refM := Module{}

	additionalConfigs := map[string][]string{
		"HTTP_FailIfMatchesRegexp": {"Test1"},
	}
	combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

	if len(refM.HTTP.FailIfMatchesRegexp) != 0 {
		t.Fatal("The reference module is not expected to get modified.")
	}
	if len(combinedM.HTTP.FailIfMatchesRegexp) != 1 {
		t.Fatal("The combined module is expected to contain one element for Http.FailIfMatchesRegexp.")
	}
	if combinedM.HTTP.FailIfMatchesRegexp[0] != "Test1" {
		t.Fatal("The combined module is expected to contain the given regex.")
	}
}

func TestCombineModulesWithStrings(t *testing.T) {
	refM := Module{}

	additionalConfigs := map[string][]string{
		"HTTP_FailIfMatchesRegexp": {"Test1", "Test2"},
	}
	combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

	if len(refM.HTTP.FailIfMatchesRegexp) != 0 {
		t.Fatal("The reference module is not expected to get modified.")
	}
	if len(combinedM.HTTP.FailIfMatchesRegexp) != 2 {
		t.Fatal("The combined module is expected to contain two element for Http.FailIfMatchesRegexp.")
	}
	if combinedM.HTTP.FailIfMatchesRegexp[0] != "Test1" && combinedM.HTTP.FailIfMatchesRegexp[1] != "Test2" {
		t.Fatal("The combined module is expected to contain the given regex.")
	}
}

func TestCombineModulesWithTwoKeys(t *testing.T) {
	refM := Module{}

	additionalConfigs := map[string][]string{
		"HTTP_FailIfMatchesRegexp":    {"Test1", "Test2"},
		"HTTP_FailIfNotMatchesRegexp": {"TestNot1", "TestNot2"},
	}
	combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

	if len(refM.HTTP.FailIfMatchesRegexp) != 0 &&
		len(refM.HTTP.FailIfNotMatchesRegexp) != 0 {
		t.Fatal("The reference module is not expected to get modified.")
	}
	if len(combinedM.HTTP.FailIfMatchesRegexp) != 2 &&
		len(refM.HTTP.FailIfNotMatchesRegexp) != 2 {
		t.Fatal("The combined module is expected to contain two element for each," +
			"Http.FailIfMatchesRegexp and Http.FailIfNotMatchesRegexp.")
	}
	if combinedM.HTTP.FailIfMatchesRegexp[0] != "Test1" && combinedM.HTTP.FailIfMatchesRegexp[1] != "Test2" &&
		combinedM.HTTP.FailIfNotMatchesRegexp[0] != "TestNot1" && combinedM.HTTP.FailIfNotMatchesRegexp[1] != "TestNot2" {
		t.Fatal("The combined module is expected to contain the given regexes.")
	}
}

func TestCombineModulesWithBool(t *testing.T) {
	refM := Module{}

	additionalConfigs := map[string][]string{
		"TCP_TLSConfig_InsecureSkipVerify": {"true"},
	}
	combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

	if refM.TCP.TLSConfig.InsecureSkipVerify != false {
		t.Fatal("The reference module is not expected to get modified.")
	}
	if combinedM.TCP.TLSConfig.InsecureSkipVerify != true {
		t.Fatal("The combined module is expected to have TCP.TLSConfig.InsecureSkipVerify adjusted.")
	}
}

func TestCombineModulesWithInt(t *testing.T) {
	refM := Module{}

	additionalConfigs := map[string][]string{
		"HTTP_ValidStatusCodes": {"200", "300"},
	}
	combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

	if len(refM.HTTP.ValidStatusCodes) != 0 {
		t.Fatal("The reference module is not expected to get modified.")
	}
	if len(combinedM.HTTP.ValidStatusCodes) != 2 {
		t.Fatal("The combined module is expected to contain two element for Http.FailIfMatchesRegexp.")
	}
	if combinedM.HTTP.ValidStatusCodes[0] != 200 && combinedM.HTTP.ValidStatusCodes[1] != 300 {
		t.Fatal("The combined module is expected to contain the given valid status codes.")
	}
}

func TestCombineModulesWithUnexistingKeys(t *testing.T) {
	refM := Module{}

	additionalConfigs := map[string][]string{
		"Something_Fancy":                  {"True"}, // should be ignored
		"TCP_TLSConfig_InsecureSkipVerify": {"true"}, // should be applied
	}
	combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

	if refM.TCP.TLSConfig.InsecureSkipVerify != false {
		t.Fatal("The reference module is not expected to get modified.")
	}
	if combinedM.TCP.TLSConfig.InsecureSkipVerify != true {
		t.Fatal("The combined module is expected to have TCP.TLSConfig.InsecureSkipVerify adjusted.")
	}
}

func TestCombineModules(t *testing.T) {
  refM := Module{
    HTTP: HTTPProbe{
      FailIfNotMatchesRegexp: []string{"Test1"},
    },
    TCP: TCPProbe{
      TLSConfig: config.TLSConfig{
        InsecureSkipVerify: true,
      },
    },
  }

  additionalConfigs := map[string][]string{
    "TCP_TLSConfig_InsecureSkipVerify": {"false"},
    "HTTP_FailIfNotMatchesRegexp":      {"Test2"},
  }
  combinedM := refM.Combine(additionalConfigs, log.NewNopLogger())

  if refM.TCP.TLSConfig.InsecureSkipVerify != true {
    t.Fatal("The reference module is not expected to get modified.")
  }
  if len(refM.HTTP.FailIfNotMatchesRegexp) != 1 {
    t.Fatal("The reference module is not expected to get modified.")
  }
  if refM.HTTP.FailIfNotMatchesRegexp[0] != "Test1" {
    t.Fatal("The reference module is not expected to get modified.")
  }
  if len(combinedM.HTTP.FailIfNotMatchesRegexp) != 2 {
    t.Fatal("The combined module is expected to contain two element for Http.FailIfNotMatchesRegexp.")
  }
  if combinedM.TCP.TLSConfig.InsecureSkipVerify != false {
    t.Fatal("The combined module is expected to have TCP.TLSConfig.InsecureSkipVerify adjusted.")
  }
  if combinedM.HTTP.FailIfNotMatchesRegexp[0] != "Test1" && combinedM.HTTP.FailIfNotMatchesRegexp[1] != "Test2" {
    t.Fatal("The combined module is expected to contain the given regex.")
  }
}
