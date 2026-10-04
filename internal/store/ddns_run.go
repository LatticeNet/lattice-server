package store

import (
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ddnsRunOutcomeEqual compares two profiles with their run clock and update
// time cleared and their errors compared by ddnsErrorClass.
func ddnsRunOutcomeEqual(a, b model.DDNSProfile) bool {
	if ddnsErrorClass(a.LastError) != ddnsErrorClass(b.LastError) {
		return false
	}
	a.LastRunAt, b.LastRunAt = time.Time{}, time.Time{}
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	a.LastError, b.LastError = "", ""
	return reflect.DeepEqual(a, b)
}

// ddnsErrorVolatile matches an HTTP status, which ddnsErrorClass keeps, or a
// word that holds a digit, which it drops.
var ddnsErrorVolatile = regexp.MustCompile(`status [0-9]{3}\b|[A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]*`)

// ddnsErrorClassLineMax bounds each line of a class.
const ddnsErrorClassLineMax = 256

// ddnsErrorClass reduces a DDNS error to what says which failure it is. A
// provider's text carries what changes on every attempt: a webhook body or
// Cloudflare's errors JSON can hold a request id, a timestamp or a retry
// countdown, and a network error names the address it dialled. Compared raw,
// every retry of the same failure looks new and is written at once. The class
// keeps each HTTP status ("status 503") and the words without digits, turns
// every word that holds a digit (ids, hex, UUIDs, times, counters, addresses)
// into "#", and cuts each line, one per failed record, at
// ddnsErrorClassLineMax bytes. Two failures that differ only past that cut,
// or only in digits, count as one; the cost is that the newer text waits for
// the next write instead of being written at once. Only that decision uses
// the class: the profile keeps the full text for display.
func ddnsErrorClass(msg string) string {
	if msg == "" {
		return ""
	}
	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		line = ddnsErrorVolatile.ReplaceAllStringFunc(line, func(m string) string {
			if strings.HasPrefix(m, "status ") {
				return m
			}
			return "#"
		})
		if len(line) > ddnsErrorClassLineMax {
			line = line[:ddnsErrorClassLineMax]
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
