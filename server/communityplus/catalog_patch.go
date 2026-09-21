package communityplus

import "strings"

// comparePatchVersions compares conservative dotted-numeric package versions.
// It deliberately refuses versions with prerelease/build/vendor text so patch
// automation can never guess an ordering and accidentally downgrade a host.
func comparePatchVersions(current, candidate string) (int, bool) {
	parse := func(v string) ([]string, bool) {
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "v")
		if v == "" {
			return nil, false
		}
		parts := strings.Split(v, ".")
		for i, part := range parts {
			if part == "" {
				return nil, false
			}
			for _, r := range part {
				if r < '0' || r > '9' {
					return nil, false
				}
			}
			part = strings.TrimLeft(part, "0")
			if part == "" {
				part = "0"
			}
			parts[i] = part
		}
		return parts, true
	}

	a, ok := parse(current)
	if !ok {
		return 0, false
	}
	b, ok := parse(candidate)
	if !ok {
		return 0, false
	}
	count := len(a)
	if len(b) > count {
		count = len(b)
	}
	for i := 0; i < count; i++ {
		av, bv := "0", "0"
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if len(av) != len(bv) {
			if len(av) < len(bv) {
				return -1, true
			}
			return 1, true
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	return 0, true
}

func safePatchUpgrade(current, candidate CatalogEntry) bool {
	if current.Provider != candidate.Provider || current.Provider != CatalogProviderWinget {
		return false
	}
	if !strings.EqualFold(current.PackageIdentifier, candidate.PackageIdentifier) {
		return false
	}
	if current.InstallerType != candidate.InstallerType {
		return false
	}
	cmp, ok := comparePatchVersions(current.Version, candidate.Version)
	return ok && cmp < 0
}
