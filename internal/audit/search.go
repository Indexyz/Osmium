package audit

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Query selects events in [From, To). Empty string filters match everything.
type Query struct {
	From, To  time.Time
	Action    string
	User      string // display name (case-insensitive) or internal user ID
	Actor     string
	SessionID string
	Target    string
	Limit     int
	Cursor    string // from a previous Page.Next
}

// Page is one page of results, ordered by segment start time and then by
// time within a segment. Next is empty when the range is exhausted; a page
// may hold fewer than Limit events and still have a Next.
type Page struct {
	Events []Event `json:"items"`
	Next   string  `json:"next_cursor,omitempty"`
}

const (
	// MaxLimit bounds one page.
	MaxLimit = 1000
	// MaxRange bounds one query's time range.
	MaxRange = 31 * 24 * time.Hour
	// maxLine bounds a single stored line; longer lines are skipped.
	maxLine = 1 << 20
	// maxRemoteSegs bounds object downloads per call; Search then returns a
	// cursor so slow scans proceed page by page.
	maxRemoteSegs = 64
)

// ErrBadQuery reports invalid query parameters or cursor.
var ErrBadQuery = errors.New("audit: bad query")

// cursor resumes at byte offset off of segment seg; off < 0 means the
// segment is done.
type cursor struct {
	seg string
	off int64
}

func (c cursor) encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.seg + "|" + strconv.FormatInt(c.off, 10)))
}

func decodeCursor(s string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, fmt.Errorf("%w: cursor", ErrBadQuery)
	}
	seg, off, ok := strings.Cut(string(raw), "|")
	n, err := strconv.ParseInt(off, 10, 64)
	if _, valid := parseSeg(seg); !ok || err != nil || !valid || n < -1 {
		return cursor{}, fmt.Errorf("%w: cursor", ErrBadQuery)
	}
	return cursor{seg: seg, off: n}, nil
}

func (q Query) match(e *Event) bool {
	if e.Time.Before(q.From) || !e.Time.Before(q.To) {
		return false
	}
	return (q.Action == "" || e.Action == q.Action) &&
		(q.User == "" || strings.EqualFold(e.User, q.User) || e.Actor == "user:"+q.User) &&
		(q.Actor == "" || e.Actor == q.Actor) &&
		(q.SessionID == "" || e.SessionID == q.SessionID) &&
		(q.Target == "" || e.Target == q.Target)
}

// Search scans the segments of the days overlapping [From, To): local ones
// (pending upload, or all of them without a Store) and uploaded ones.
func (l *Logger) Search(ctx context.Context, q Query) (Page, error) {
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return Page{}, fmt.Errorf("%w: from must be before to", ErrBadQuery)
	}
	if q.To.Sub(q.From) > MaxRange {
		return Page{}, fmt.Errorf("%w: range longer than %v", ErrBadQuery, MaxRange)
	}
	if q.Limit <= 0 || q.Limit > MaxLimit {
		return Page{}, fmt.Errorf("%w: limit must be 1..%d", ErrBadQuery, MaxLimit)
	}
	var cur cursor
	if q.Cursor != "" {
		c, err := decodeCursor(q.Cursor)
		if err != nil {
			return Page{}, err
		}
		cur = c
	}
	var page Page
	remote := 0
	last := dayOf(q.To.Add(-time.Nanosecond))
	for day := dayOf(q.From); day <= last; day = nextDay(day) {
		if cur.seg != "" && day < cur.seg[:len(time.DateOnly)] {
			continue
		}
		segs, err := l.segsOf(ctx, day)
		if err != nil {
			return Page{}, err
		}
		for _, seg := range segs {
			off := int64(0)
			switch {
			case seg < cur.seg:
				continue
			case seg == cur.seg:
				if cur.off < 0 {
					continue
				}
				off = cur.off
			}
			if start, _ := parseSeg(seg); !start.Before(q.To) {
				return page, nil // later segments start even later
			}
			if remote >= maxRemoteSegs {
				page.Next = cursor{seg: seg, off: off}.encode()
				return page, nil
			}
			next, full, fromStore, err := l.scan(ctx, seg, off, q, &page)
			if err != nil {
				return Page{}, err
			}
			if fromStore {
				remote++
			}
			if full {
				page.Next = cursor{seg: seg, off: next}.encode()
				return page, nil
			}
		}
	}
	return page, nil
}

func nextDay(day string) string {
	t, _ := time.Parse(time.DateOnly, day)
	return dayOf(t.Add(24 * time.Hour))
}

// segsOf lists one day's segments from both places. Local is listed first:
// a segment is uploaded before its local copy is removed, so it is always
// seen in at least one of the two listings.
func (l *Logger) segsOf(ctx context.Context, day string) ([]string, error) {
	segs := l.localSegs(day)
	if l.cfg.Store != nil {
		remote, err := l.storeSegs(ctx, day)
		if err != nil {
			return nil, fmt.Errorf("audit: list %s: %w", day, err)
		}
		segs = append(segs, remote...)
	}
	sort.Strings(segs)
	out := segs[:0]
	for i, s := range segs {
		if i == 0 || s != segs[i-1] {
			out = append(out, s)
		}
	}
	return out, nil
}

// open returns a reader positioned at off, preferring the local copy.
func (l *Logger) open(ctx context.Context, seg string, off int64) (io.ReadCloser, bool, error) {
	f, err := os.Open(filepath.Join(l.cfg.Dir, filepath.FromSlash(seg)))
	if err == nil {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			return nil, false, err
		}
		return f, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) || l.cfg.Store == nil {
		return nil, false, err
	}
	obj, err := l.cfg.Store.Get(ctx, seg+gzSuffix)
	if err != nil {
		return nil, true, err
	}
	zr, err := gzip.NewReader(obj)
	if err != nil {
		obj.Close()
		return nil, true, err
	}
	if _, err := io.CopyN(io.Discard, zr, off); err != nil && err != io.EOF {
		obj.Close()
		return nil, true, err
	}
	return readCloser{zr, obj}, true, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// scan reads complete lines of seg from off, appending matches. It returns
// the offset after the last consumed line, whether the page filled, and
// whether the segment came from the Store.
func (l *Logger) scan(ctx context.Context, seg string, off int64, q Query, page *Page) (int64, bool, bool, error) {
	rc, fromStore, err := l.open(ctx, seg, off)
	if errors.Is(err, fs.ErrNotExist) {
		return off, false, fromStore, nil // removed by retention meanwhile
	}
	if err != nil {
		return off, false, fromStore, fmt.Errorf("audit: read %s: %w", seg, err)
	}
	defer rc.Close()
	r := bufio.NewReaderSize(rc, 64*1024)
	for {
		line, n, err := readLine(r)
		if err == io.EOF {
			// A trailing line without '\n' is still being written (or was
			// torn by a crash); stop before it.
			return off, false, fromStore, nil
		}
		if err != nil {
			return off, false, fromStore, fmt.Errorf("audit: read %s: %w", seg, err)
		}
		off += n
		var e Event
		if line != nil && json.Unmarshal(line, &e) == nil && q.match(&e) {
			page.Events = append(page.Events, e)
			if len(page.Events) == q.Limit {
				return off, true, fromStore, nil
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
