package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The config file holds defaults for both commands, one option per line,
// with the long option names:
//
//	# cmsrecon defaults
//	wordfence-key = 0123456789abcdef
//	proxy = http://127.0.0.1:8080
//	throttle = 200ms
//	stealthy = true
//
// It is read from --config FILE, else $CMSRECON_CONFIG, else
// <user config dir>/cmsrecon/config (%AppData%\cmsrecon\config on
// Windows, ~/.config/cmsrecon/config on Linux). Options on the command line
// override it. Each command takes the options it knows; an option neither
// command knows is an error, so that a typo does not go unnoticed.

// ConfigEnv names the environment variable that points at the config file.
const ConfigEnv = "CMSRECON_CONFIG"

// updateOnlyOptions are the config keys only the update command uses.
var updateOnlyOptions = map[string]bool{"wordfence-key": true, "sources": true}

// scanOnlyOptions are the scan's options, read from its help text, so
// that the update command can tell a scan option from a typo.
var scanOnlyOptions = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range regexp.MustCompile(`--([a-z][a-z0-9-]+)|(?m)^ +-([a-zA-Z]),`).FindAllStringSubmatch(ScanUsage, -1) {
		m[f[1]+f[2]] = true
	}
	return m
}()

// DefaultConfigFile is where the config file is looked for by default.
func DefaultConfigFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "cmsrecon", "config")
}

// configArgs turns the config file into arguments for fs, to put before
// the command line's. It also returns the file's path, or "" when there
// is none.
func configArgs(args []string, flags *flag.FlagSet) ([]string, string, error) {
	file, explicit := configPath(args)
	if file == "" || strings.EqualFold(file, "none") {
		return nil, "", nil
	}
	f, err := os.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("config file: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimLeft(strings.TrimSpace(key), "-")
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if !ok || key == "" {
			return nil, "", fmt.Errorf("%s:%d: expected \"option = value\"", file, n)
		}
		if key == "config" {
			continue
		}
		if flags.Lookup(key) == nil {
			if updateOnlyOptions[key] || scanOnlyOptions[key] {
				continue // the other command's
			}
			return nil, "", fmt.Errorf("%s:%d: unknown option %q", file, n, key)
		}
		out = append(out, "--"+key+"="+value)
	}
	if err := sc.Err(); err != nil {
		return nil, "", fmt.Errorf("config file: %w", err)
	}
	return out, file, nil
}

// configPath finds --config FILE (or --config=FILE) in the arguments,
// else $CMSRECON_CONFIG, else the default location. explicit is true when
// the user named the file, which then has to exist.
func configPath(args []string) (path string, explicit bool) {
	for i, a := range args {
		a = strings.TrimLeft(a, "-")
		if v, ok := strings.CutPrefix(a, "config="); ok {
			return v, true
		}
		if a == "config" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	if v := os.Getenv(ConfigEnv); v != "" {
		return v, true
	}
	return DefaultConfigFile(), false
}
