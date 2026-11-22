package audit

import (
	"strings"
	"time"

	"github.com/indexyz/osmium/internal/tunnel"
)

// Events are written to segments. A segment is named
// "YYYY-MM-DD/HHMMSS.nnnnnnnnn-<server_id>.jsonl" after its UTC start time,
// so names sort by start time and the same name is used locally and (with a
// ".gz" suffix) in object storage.
const (
	segSuffix     = ".jsonl"
	gzSuffix      = ".gz"
	segTimeLayout = "150405.000000000"
)

func segName(start time.Time, server string) string {
	start = start.UTC()
	return start.Format(time.DateOnly) + "/" + start.Format(segTimeLayout) + "-" + server + segSuffix
}

// parseSeg validates a segment name and returns its start time. Strict
// parsing also keeps cursor-supplied names from escaping the audit dir.
func parseSeg(name string) (time.Time, bool) {
	day, rest, ok := strings.Cut(name, "/")
	if !ok {
		return time.Time{}, false
	}
	base, ok := strings.CutSuffix(rest, segSuffix)
	if !ok || len(base) < len(segTimeLayout)+2 || base[len(segTimeLayout)] != '-' || !tunnel.ValidID(base[len(segTimeLayout)+1:]) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateOnly+" "+segTimeLayout, day+" "+base[:len(segTimeLayout)])
	if err != nil || segName(t, base[len(segTimeLayout)+1:]) != name {
		return time.Time{}, false
	}
	return t, true
}

func dayOf(t time.Time) string { return t.UTC().Format(time.DateOnly) }

func validDay(s string) bool {
	t, err := time.Parse(time.DateOnly, s)
	return err == nil && dayOf(t) == s
}
