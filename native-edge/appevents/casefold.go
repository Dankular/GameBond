package appevents

import "strings"

// casefold is Python's str.casefold.
func casefold(s string) string {
	var b strings.Builder
	for _, r := range s {
		if f, ok := casefoldTable[r]; ok {
			b.WriteString(f)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Casefold is Python's str.casefold, for packages that must match it.
func Casefold(s string) string { return casefold(s) }
