package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Profile is the JSON sandbox profile (see README.md for the format).
type Profile struct {
	Filesystem  filesystemCfg  `json:"filesystem"`
	Network     networkCfg     `json:"network"`
	Environment environmentCfg `json:"environment"`
}

type filesystemCfg struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
	Deny  []string `json:"deny"`
}

type networkCfg struct {
	AllowDomain []string `json:"allow_domain"`
	DenyDomain  []string `json:"deny_domain"`
	OpenPorts   []int    `json:"open_ports"`
}

type environmentCfg struct {
	AllowVars []string `json:"allow_vars"`
	DenyVars  []string `json:"deny_vars"`
}

// Config is the effective configuration derived from a profile, with
// defaults filling whatever the profile leaves unset.
type Config struct {
	Read, Write, Deny         []string
	Workdir                   string
	AllowDomains, DenyDomains []string
	OpenPorts                 []int
	AllowEnv, DenyEnv         []string
}

// LoadProfile reads a profile JSON file; the path must not be empty
// (run requires --profile).
func LoadProfile(path string) (Profile, error) {
	var p Profile
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read profile %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse profile %s: %w", path, err)
	}
	return p, nil
}

// ConfigFromProfile applies the defaults to a profile. The workdir is
// always the current directory.
func ConfigFromProfile(p Profile) Config {
	cfg := Config{
		Read:         p.Filesystem.Read,
		Write:        p.Filesystem.Write,
		Deny:         p.Filesystem.Deny,
		AllowDomains: p.Network.AllowDomain,
		DenyDomains:  p.Network.DenyDomain,
		OpenPorts:    p.Network.OpenPorts,
		AllowEnv:     p.Environment.AllowVars,
		DenyEnv:      p.Environment.DenyVars,
	}
	if wd, err := os.Getwd(); err == nil {
		cfg.Workdir = wd
	}
	return cfg
}
