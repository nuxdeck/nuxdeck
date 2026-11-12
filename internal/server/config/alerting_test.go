// SPDX-License-Identifier: AGPL-3.0-only

package config

import "testing"

func TestAlertingConfigDefaultsAndValidation(t *testing.T) {
	d := Defaults()
	if d.Alerting.RepeatIntervalMinutes != 240 || d.Alerting.QueueSize != 256 || d.Alerting.Workers != 4 || d.Server.PublicURL != "" {
		t.Errorf("defaults = %+v / %+v", d.Alerting, d.Server)
	}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"default", func(*Config) {}, true},
		{"public url ok", func(c *Config) { c.Server.PublicURL = "https://nux.example.com" }, true},
		{"public url with port and slash", func(c *Config) { c.Server.PublicURL = "https://nux.example.com:8443/" }, true},
		{"public url http", func(c *Config) { c.Server.PublicURL = "http://nux.example.com" }, false},
		{"public url path", func(c *Config) { c.Server.PublicURL = "https://nux.example.com/app" }, false},
		{"public url creds", func(c *Config) { c.Server.PublicURL = "https://u:p@nux.example.com" }, false},
		{"public url query", func(c *Config) { c.Server.PublicURL = "https://nux.example.com/?x=1" }, false},
		{"public url no host", func(c *Config) { c.Server.PublicURL = "https://" }, false},
		{"repeat off", func(c *Config) { c.Alerting.RepeatIntervalMinutes = 0 }, true},
		{"repeat negative", func(c *Config) { c.Alerting.RepeatIntervalMinutes = -1 }, false},
		{"queue zero", func(c *Config) { c.Alerting.QueueSize = 0 }, false},
		{"workers too many", func(c *Config) { c.Alerting.Workers = 65 }, false},
	} {
		c := Defaults()
		tc.mut(&c)
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	cfg, err := Load("/nonexistent/nuxd.yaml", false, env(map[string]string{"NUXD_PUBLIC_URL": "https://nux.example.com"}))
	if err != nil || cfg.Server.PublicURL != "https://nux.example.com" {
		t.Errorf("env override = %q, %v", cfg.Server.PublicURL, err)
	}
}
