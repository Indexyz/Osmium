package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/coder/websocket"
)

const (
	// MuxGenHeaderSize is the 4-byte big-endian uint32 generation prefix placed
	// at the start of every binary WebSocket frame on the unified Agent tunnel.
	MuxGenHeaderSize = 4

	defaultMaxPipeBuf = 256 * 1024
)

// ErrInvalidBinaryFrame is returned when a peer sends a malformed binary frame
// (too short, mux_gen==0, or future generation before mux.open).
var ErrInvalidBinaryFrame = errors.New("tunnel: invalid binary frame")

// Demux multiplexes JSON control messages (WebSocket text frames) and on-demand
// generational smux v2 sessions (WebSocket binary frames prefixed with a 4-byte
// mux_gen) over one long-lived mTLS WebSocket connection.
//
// In the idle state (no active SSH sessions), Demux holds no smux.Session and
// runs a single reader goroutine with minimal per-connection overhead.
type Demux struct {
	ws        *websocket.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	maxText   int64
	maxBinary int64

	// writeMu serializes Text (mux.open/mux.close/session.close) and Binary
	// frames so control transitions always arrive in TCP order before subsequent
	// generation bytes.
	writeMu sync.Mutex

	mu         sync.Mutex
	lastGen    uint32
	activeGen  uint32
	activePipe *genPipe
	closed     bool
}

// NewDemux wraps ws for unified text + generational binary multiplexing.
// ctx must be the tunnel epoch's parent context, never a single SSH session's.
func NewDemux(ctx context.Context, ws *websocket.Conn, maxText, maxBinary int64) *Demux {
	if maxText <= 0 {
		maxText = 64 * 1024
	}
	if maxBinary <= 0 {
		maxBinary = 128 * 1024
	}
	ws.SetReadLimit(maxBinary)
	dctx, cancel := context.WithCancel(ctx)
	return &Demux{
		ws:        ws,
		ctx:       dctx,
		cancel:    cancel,
		maxText:   maxText,
		maxBinary: maxBinary,
	}
}

// SendText writes one JSON control text frame atomically with respect to
// binary generation writes.
func (d *Demux) SendText(ctx context.Context, data []byte) error {
	if int64(len(data)) > d.maxText {
		return errors.New("tunnel: control text frame exceeds limit")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.ws.Write(ctx, websocket.MessageText, data)
}

// Activate prepares a new strictly-increasing smux generation and returns its
// GenConn. Any previous active generation pipe is closed without closing the
// underlying WebSocket.
//
// When sending mux.open on the Server side, call ActivateWithText so the
// generation is installed before releasing writeMu and before any binary frame
// of that generation can be written.
func (d *Demux) Activate(gen uint32, maxPipeBuf int) (*GenConn, error) {
	if gen == 0 {
		return nil, errors.New("tunnel: mux generation must be positive")
	}
	if maxPipeBuf <= 0 {
		maxPipeBuf = defaultMaxPipeBuf
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, io.ErrClosedPipe
	}
	if gen <= d.lastGen {
		return nil, fmt.Errorf("tunnel: non-monotonic mux generation %d <= %d", gen, d.lastGen)
	}
	if d.activePipe != nil {
		d.activePipe.close()
	}
	p := newGenPipe(maxPipeBuf)
	d.lastGen = gen
	d.activeGen = gen
	d.activePipe = p
	return &GenConn{demux: d, gen: gen, pipe: p}, nil
}

// ActivateAndSendText atomically installs generation gen and writes the
// mux.open text frame while holding writeMu so no binary frame of gen can
// overtake the text frame on the wire.
func (d *Demux) ActivateAndSendText(ctx context.Context, gen uint32, maxPipeBuf int, textFrame []byte) (*GenConn, error) {
	if int64(len(textFrame)) > d.maxText {
		return nil, errors.New("tunnel: control text frame exceeds limit")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	gc, err := d.Activate(gen, maxPipeBuf)
	if err != nil {
		return nil, err
	}
	if err := d.ws.Write(ctx, websocket.MessageText, textFrame); err != nil {
		d.Deactivate(gen)
		return nil, err
	}
	return gc, nil
}

// Deactivate closes the active pipe if its generation matches gen. The
// underlying WebSocket remains open and idle.
func (d *Demux) Deactivate(gen uint32) {
	d.mu.Lock()
	var p *genPipe
	if d.activeGen == gen && d.activePipe != nil {
		p = d.activePipe
		d.activePipe = nil
	}
	d.mu.Unlock()
	if p != nil {
		p.close()
	}
}

// Close closes the demuxer and any active generation pipe, cancelling the
// demux context. The caller still closes the underlying WebSocket with the
// desired close status.
func (d *Demux) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	p := d.activePipe
	d.activePipe = nil
	d.mu.Unlock()
	if p != nil {
		p.close()
	}
	d.cancel()
}

// Run executes the single WebSocket read loop until an error occurs, onText
// returns an error, or the context ends.
//
// onActivity (if non-nil) is called whenever any valid frame is received.
// onText is called synchronously in the read loop so mux.open installs the new
// generation before the next binary frame is read.
func (d *Demux) Run(onText func([]byte) error, onActivity func()) error {
	defer d.Close()
	for {
		typ, data, err := d.ws.Read(d.ctx)
		if err != nil {
			return err
		}
		if onActivity != nil {
			onActivity()
		}
		switch typ {
		case websocket.MessageText:
			if int64(len(data)) > d.maxText {
				return errors.New("tunnel: control text frame exceeds limit")
			}
			if err := onText(data); err != nil {
				return err
			}
		case websocket.MessageBinary:
			if err := d.dispatchBinary(data); err != nil {
				return err
			}
		default:
			return ErrInvalidBinaryFrame
		}
	}
}

func (d *Demux) dispatchBinary(frame []byte) error {
	if len(frame) < MuxGenHeaderSize {
		return fmt.Errorf("%w: frame shorter than 4-byte generation prefix", ErrInvalidBinaryFrame)
	}
	gen := binary.BigEndian.Uint32(frame[:MuxGenHeaderSize])
	if gen == 0 {
		return fmt.Errorf("%w: zero mux generation", ErrInvalidBinaryFrame)
	}
	d.mu.Lock()
	last := d.lastGen
	active := d.activeGen
	pipe := d.activePipe
	closed := d.closed
	d.mu.Unlock()

	if closed {
		return io.ErrClosedPipe
	}
	if gen > last {
		// Peer sent binary data for a generation that was never opened.
		return fmt.Errorf("%w: unexpected future mux generation %d (last=%d)", ErrInvalidBinaryFrame, gen, last)
	}
	if pipe == nil || gen != active {
		// Late in-flight frame from an older retired generation: safely drop.
		return nil
	}
	payload := frame[MuxGenHeaderSize:]
	if len(payload) == 0 {
		return nil
	}
	// Copy is unnecessary because ws.Read allocates a fresh slice per message.
	// Push respects both pipe close and demux context cancellation.
	_ = pipe.push(d.ctx, payload)
	return nil
}

// GenConn is the io.ReadWriteCloser handed to smux.Client / smux.Server for a
// single generation. It also implements WriteBuffers so smux skips allocating
// its 64 KiB sendLoop staging buffer and performs single-frame scatter-gather
// WebSocket writes.
//
// Closing a GenConn ONLY ends this mux generation; it NEVER closes the outer
// shared WebSocket connection.
type GenConn struct {
	demux *Demux
	gen   uint32
	pipe  *genPipe
}

// Read reads smux wire bytes belonging to this generation.
func (g *GenConn) Read(p []byte) (int, error) {
	return g.pipe.read(p)
}

// Write writes one binary WebSocket frame prefixed with this generation's ID.
func (g *GenConn) Write(p []byte) (int, error) {
	return g.WriteBuffers([][]byte{p})
}

// WriteBuffers satisfies smux's scatter-gather interface so smux avoids its
// per-session 64 KiB buffer. Returns the payload bytes written (excluding the
// 4-byte mux_gen prefix), matching smux.Session.sendLoop's accounting.
func (g *GenConn) WriteBuffers(v [][]byte) (int, error) {
	if g.pipe.isClosed() {
		return 0, io.ErrClosedPipe
	}
	var total int
	for _, b := range v {
		total += len(b)
	}
	if total == 0 {
		return 0, nil
	}
	var hdr [MuxGenHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:], g.gen)

	g.demux.writeMu.Lock()
	defer g.demux.writeMu.Unlock()
	if g.pipe.isClosed() {
		return 0, io.ErrClosedPipe
	}
	w, err := g.demux.ws.Writer(g.demux.ctx, websocket.MessageBinary)
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(hdr[:]); err != nil {
		_ = w.Close()
		return 0, err
	}
	for _, b := range v {
		if len(b) == 0 {
			continue
		}
		if _, err := w.Write(b); err != nil {
			_ = w.Close()
			return 0, err
		}
	}
	if err := w.Close(); err != nil {
		return 0, err
	}
	return total, nil
}

// Close ends only this generation's pipe; the outer WebSocket stays open.
func (g *GenConn) Close() error {
	g.demux.Deactivate(g.gen)
	g.pipe.close()
	return nil
}

// genPipe is a bounded FIFO byte-chunk queue connecting the Demux read loop to
// one smux.Session's recvLoop. Allocated only while a generation is active.
type genPipe struct {
	mu      sync.Mutex
	maxBuf  int
	chunks  [][]byte
	size    int
	closed  bool
	readCh  chan struct{} // notified when data arrives or pipe closes
	writeCh chan struct{} // notified when space opens or pipe closes
}

func newGenPipe(maxBuf int) *genPipe {
	return &genPipe{
		maxBuf:  maxBuf,
		readCh:  make(chan struct{}, 1),
		writeCh: make(chan struct{}, 1),
	}
}

func signalCh(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (p *genPipe) isClosed() bool {
	p.mu.Lock()
	c := p.closed
	p.mu.Unlock()
	return c
}

func (p *genPipe) close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.chunks = nil
		p.size = 0
	}
	p.mu.Unlock()
	signalCh(p.readCh)
	signalCh(p.writeCh)
}

func (p *genPipe) push(ctx context.Context, chunk []byte) error {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return io.ErrClosedPipe
		}
		// Allow pushing when queue is empty even if a single frame > maxBuf
		// so a valid max-sized smux frame can never deadlock.
		if p.size == 0 || p.size+len(chunk) <= p.maxBuf {
			p.chunks = append(p.chunks, chunk)
			p.size += len(chunk)
			p.mu.Unlock()
			signalCh(p.readCh)
			return nil
		}
		p.mu.Unlock()
		select {
		case <-p.writeCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *genPipe) read(dst []byte) (int, error) {
	for {
		p.mu.Lock()
		if len(p.chunks) > 0 {
			head := p.chunks[0]
			n := copy(dst, head)
			if n == len(head) {
				p.chunks[0] = nil // release reference for GC
				p.chunks = p.chunks[1:]
				if len(p.chunks) == 0 {
					p.chunks = nil
				}
			} else {
				p.chunks[0] = head[n:]
			}
			p.size -= n
			p.mu.Unlock()
			signalCh(p.writeCh)
			return n, nil
		}
		if p.closed {
			p.mu.Unlock()
			return 0, io.EOF
		}
		p.mu.Unlock()
		<-p.readCh
	}
}
