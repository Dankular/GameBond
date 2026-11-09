package appauth

import (
	"errors"
	"strconv"
	"strings"
)

// parsePyInt is int(str) for the forms the netstack sends: optional sign,
// digits, surrounding whitespace, single underscores between digits.
func parsePyInt(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "_") || strings.HasSuffix(s, "_") || strings.Contains(s, "__") {
		return 0, errors.New("invalid")
	}
	return strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 10, 64)
}
