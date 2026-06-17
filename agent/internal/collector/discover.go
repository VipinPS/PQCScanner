package collector

import (
	"path/filepath"
	"sort"

	"github.com/VipinPS/pqc-platform/agent/internal/mapper"
)

// libSearchDirs are checked, in order, for each library's .so files.
// Covers common Debian/Ubuntu, RHEL/Fedora and Alpine layouts.
var libSearchDirs = []string{
	"/usr/lib/x86_64-linux-gnu",
	"/lib/x86_64-linux-gnu",
	"/usr/lib64",
	"/lib64",
	"/usr/lib",
	"/lib",
	"/usr/local/lib",
}

// DiscoverLibraries searches libSearchDirs for the libraries referenced by
// mapper.Probes (libcrypto, libssl, liboqs) and returns a map from library
// name to the best-matching .so path found. Libraries that aren't present
// on the host are omitted from the result — Collector.New skips their
// probes rather than failing.
//
// When multiple versioned files match (e.g. libcrypto.so.3 and
// libcrypto.so.1.1), the lexicographically greatest filename is preferred,
// which favors newer SONAME versions (".so.3" > ".so.1.1").
func DiscoverLibraries() map[string]string {
	found := map[string]string{}
	for _, lib := range mapper.Libraries() {
		pattern := lib + ".so*"
		var candidates []string
		for _, dir := range libSearchDirs {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern))
			candidates = append(candidates, matches...)
		}
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool {
			return filepath.Base(candidates[i]) > filepath.Base(candidates[j])
		})
		found[lib] = candidates[0]
	}
	return found
}
