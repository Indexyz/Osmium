package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// HalfConn is a net.Conn supporting write-side shutdown (TCP, smux v2 stream).
type HalfConn interface {
	net.Conn
	CloseWrite() error
}

// Relay propagates normal EOF via CloseWrite, then permits a bounded reverse
// drain. Errors/cancellation abort both directions. Close itself may be subject
// to implementation-specific internal timeouts; test under backpressure.
func Relay(ctx context.Context, a, b HalfConn, drain time.Duration) error {
	if drain <= 0 {
		return errors.New("positive drain timeout required")
	}
	var once sync.Once
	abort := func() {
		once.Do(func() {
			_ = a.SetDeadline(time.Now())
			_ = b.SetDeadline(time.Now())
			_ = b.Close()
			_ = a.Close()
		})
	}
	defer abort()
	results := make(chan error, 2)
	copyOne := func(dst, src HalfConn) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 32*1024))
		if err == nil {
			err = dst.CloseWrite()
		}
		results <- err
	}
	go copyOne(a, b)
	go copyOne(b, a)
	var first error
	select {
	case first = <-results:
	case <-ctx.Done():
		abort()
		<-results
		<-results
		return ctx.Err()
	}
	if first != nil {
		abort()
		return errors.Join(first, <-results)
	}
	timer := time.NewTimer(drain)
	defer timer.Stop()
	select {
	case second := <-results:
		return second
	case <-ctx.Done():
		abort()
		<-results
		return ctx.Err()
	case <-timer.C:
		abort()
		<-results
		return errors.New("reverse drain timeout")
	}
}
