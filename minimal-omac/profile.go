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
	Mode        string   `json:"mode"`
	AllowDomain []string `json:"allow_domain"`
	DenyDomain  []string `json:"deny_domain"`
	OpenPorts   []int    `json:"open_ports"`
}

type environmentCfg struct {
	AllowVars []string `json:"allow_vars"`
	DenyVars  []string `json:"deny_vars"`
}

// Config is the effective configuration after merging a profile with the
// run flags: lists are concatenated, scalar flags win over the profile
// when set, and defaults fill the rest.
type Config struct {
	Read, Write, Deny         []string
	NoDefaultDeny             bool
	Workdir                   string
	NetworkMode               string
	AllowDomains, DenyDomains []string
	OpenPorts                 []int
	AllowEnv, DenyEnv         []string
}

// LoadProfile reads a profile JSON file; an empty path yields the zero
// profile (defaults only, no filesystem access).
func LoadProfile(path string) (Profile, error) {
	var p Profile
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read profile %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse profile %s: %w", path, err)
	}
	return p, nil
}

func MergeConfig(p Profile, f runFlags) Config {
	cfg := Config{
		Read:          concat(p.Filesystem.Read, f.reads),
		Write:         concat(p.Filesystem.Write, f.writes),
		Deny:          concat(p.Filesystem.Deny, f.denies),
		NoDefaultDeny: f.noDefaultDeny,
		Workdir:       f.workdir,
		NetworkMode:   f.network,
		AllowDomains:  concat(p.Network.AllowDomain, f.allowDomains),
		DenyDomains:   concat(p.Network.DenyDomain, f.denyDomains),
		OpenPorts:     append(append([]int{}, p.Network.OpenPorts...), f.openPorts...),
		AllowEnv:      concat(p.Environment.AllowVars, f.allowEnv),
		DenyEnv:       concat(p.Environment.DenyVars, f.denyEnv),
	}
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = p.Network.Mode
	}
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = ModeFiltered
	}
	if cfg.Workdir == "" {
		if wd, err := os.Getwd(); err == nil {
			cfg.Workdir = wd
		}
	}
	return cfg
}

func concat(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
