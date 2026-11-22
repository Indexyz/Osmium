package audit

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Query selects events in [From, To) in ascending time order. Empty string
// filters match everything.
type Query struct {
	From, To  time.Time
	Action    string
	Actor     string
	SessionID string
	Target    string
	Limit     int
	Cursor    string // from a previous Page.Next
}

// Page is one page of results. Next is empty when the range is exhausted.
type Page struct {
	Events []Event `json:"items"`
	Next   string  `json:"next_cursor,omitempty"`
}

// MaxLimit bounds one page.
const MaxLimit = 1000

// maxLine bounds a single stored line; longer lines are skipped.
const maxLine = 1 << 20

// ErrBadQuery reports invalid query parameters or cursor.
var ErrBadQuery = errors.New("audit: bad query")

type cursor struct {
	day    string
	offset int64
}

func (c cursor) encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.day + ":" + strconv.FormatInt(c.offset, 10)))
}

func decodeCursor(s string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, ErrBadQuery
	}
	day, off, ok := strings.Cut(string(raw), ":")
	n, err := strconv.ParseInt(off, 10, 64)
	if _, perr := time.Parse(time.DateOnly, day); !ok || err != nil || perr != nil || n < 0 {
		return cursor{}, ErrBadQuery
	}
	return cursor{day: day, offset: n}, nil
}

func (q Query) match(e *Event) bool {
	if e.Time.Before(q.From) || !e.Time.Before(q.To) {
		return false
	}
	return (q.Action == "" || e.Action == q.Action) &&
		(q.Actor == "" || e.Actor == q.Actor) &&
		(q.SessionID == "" || e.SessionID == q.SessionID) &&
		(q.Target == "" || e.Target == q.Target)
}

// Search scans the daily files that overlap [From, To). Event times are the
// write times, so a day's file only holds that day's events.
func (l *Logger) Search(q Query) (Page, error) {
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return Page{}, fmt.Errorf("%w: from must be before to", ErrBadQuery)
	}
	if q.Limit <= 0 || q.Limit > MaxLimit {
		return Page{}, fmt.Errorf("%w: limit must be 1..%d", ErrBadQuery, MaxLimit)
	}
	start := cursor{day: dayOf(q.From)}
	if q.Cursor != "" {
		c, err := decodeCursor(q.Cursor)
		if err != nil {
			return Page{}, err
		}
		start = c
	}
	last := dayOf(q.To.Add(-time.Nanosecond))
	var page Page
	for _, day := range l.days() {
		if day < start.day || day > last {
			continue
		}
		off := int64(0)
		if day == start.day {
			off = start.offset
		}
		next, full, err := l.scan(day, off, q, &page)
		if err != nil {
			return Page{}, err
		}
		if full {
			page.Next = cursor{day: day, offset: next}.encode()
			return page, nil
		}
	}
	return page, nil
}

// scan reads complete lines of one day from off, appending matches. It
// returns the offset after the last consumed line and whether the page filled.
func (l *Logger) scan(day string, off int64, q Query, page *Page) (int64, bool, error) {
	f, err := os.Open(filepath.Join(l.cfg.Dir, day+fileSuffix))
	if errors.Is(err, os.ErrNotExist) {
		return off, false, nil // removed by retention meanwhile
	}
	if err != nil {
		return off, false, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return off, false, err
	}
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, n, err := readLine(r)
		if err == io.EOF {
			// A trailing line without '\n' is still being written; stop before it.
			return off, false, nil
		}
		if err != nil {
			return off, false, err
		}
		off += n
		var e Event
		if line != nil && json.Unmarshal(line, &e) == nil && q.match(&e) {
			page.Events = append(page.Events, e)
			if len(page.Events) == q.Limit {
				return off, true, nil
			}
		}
	}
}

// readLine returns one full line including '\n' and its byte length, or io.EOF
// if no complete line remains. An overlong line is consumed and returned as
// nil so the caller skips it while keeping offsets exact.
func readLine(r *bufio.Reader) ([]byte, int64, error) {
	var buf []byte
	var n int64
	for {
		chunk, err := r.ReadSlice('\n')
		n += int64(len(chunk))
		if n <= maxLine {
			buf = append(buf, chunk...)
		} else {
			buf = nil
		}
		switch {
		case err == nil:
			return buf, n, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, n, err
		}
	}
}
