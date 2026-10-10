// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// A request holds one of the MaxUpstreamInFlight places from when it is sent to the application until its response has
// been written to the client. A client that opens many requests and stops reading (an HTTP/2 stream window of zero, or a
// full TCP window) would hold their places until the write timeout, and every other visitor would be told the site is busy.
// So when no place is free, the response whose write has been stuck the longest, for at least stallGrace, is ended and its
// place goes to the new request at once: an HTTP/1 connection over TLS can take seconds more to close, because its
// close_notify waits on the same client. A slow client is left alone while there are places to spare.
const stallGrace = 5 * time.Second

var clockStart = time.Now()

// monotonic is a reading of the monotonic clock that is never 0 and never within an hour of it, so the start of a write
// (0 means none) is never taken for the clock's own start, and a step of the wall clock cannot make a write look stuck.
func monotonic() int64 { return int64(time.Hour) + int64(time.Since(clockStart)) }

// writeWatch is the client's own response writer, with the start of the write or flush in progress (0 when none).
type writeWatch struct {
	http.ResponseWriter
	since atomic.Int64
	ended bool // its place went to another request (guarded by upstreamPlaces.mu)
	// use is held while the writer is being used from outside its handler (to end the response), and gone says the handler
	// is returning, after which the writer may not be used. Releasing the place takes use first, so a handler cannot return
	// while its writer is in use; and the writer is used under this lock rather than under upstreamPlaces.mu, so a call that
	// is slow to come back holds up only that one request.
	use    sync.Mutex
	gone   bool
	cancel context.CancelFunc // cancels the request to the application
}

func (w *writeWatch) setCancel(c context.CancelFunc) {
	w.use.Lock()
	w.cancel = c
	w.use.Unlock()
}

// cut ends the response: the request to the application is cancelled, so that it stops using the application at once, and the
// write deadline is put in the past, so that an HTTP/2 stream is reset and an HTTP/1 connection's pending write fails. It does
// nothing if the handler is already returning.
func (w *writeWatch) cut() {
	w.use.Lock()
	defer w.use.Unlock()
	if w.gone {
		return
	}
	if w.cancel != nil {
		w.cancel()
	}
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now())
}

type writeWatchKey struct{}

func (w *writeWatch) Write(b []byte) (int, error) {
	w.since.Store(monotonic())
	n, err := w.ResponseWriter.Write(b)
	w.since.Store(0)
	return n, err
}

func (w *writeWatch) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		w.since.Store(monotonic())
		f.Flush()
		w.since.Store(0)
	}
}

func (w *writeWatch) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// upstreamPlaces are the places at the upstream and the requests that hold them.
type upstreamPlaces struct {
	free chan struct{}
	mu   sync.Mutex
	held map[*writeWatch]struct{}
	// ending counts the ended responses still finishing after their place was given away; it is kept to an eighth of the
	// places, so that the application never has many more requests at once than it was given.
	ending, maxEnding int
}

func newUpstreamPlaces(n int) *upstreamPlaces {
	return &upstreamPlaces{free: make(chan struct{}, n), held: make(map[*writeWatch]struct{}, n), maxEnding: max(1, n/8)}
}

// acquire takes a place for a request whose response goes to w (nil if it is not watched). When none is free it takes
// the place of a stuck response; reclaimed says whether it did.
func (p *upstreamPlaces) acquire(w *writeWatch) (ok, reclaimed bool) {
	select {
	case p.free <- struct{}{}:
		if w != nil {
			p.mu.Lock()
			p.held[w] = struct{}{}
			p.mu.Unlock()
		}
		return true, false
	default:
	}
	ok = p.reclaim(w)
	return ok, ok
}

// release gives the place back, unless it went to another request. It waits for a response that is being ended to be done with
// the writer, and from then on none will touch it.
func (p *upstreamPlaces) release(w *writeWatch) {
	if w != nil {
		w.use.Lock()
		w.gone = true
		w.use.Unlock()
		p.mu.Lock()
		if w.ended {
			p.ending--
			p.mu.Unlock()
			return
		}
		delete(p.held, w)
		p.mu.Unlock()
	}
	<-p.free
}

// reclaim ends the response whose write has been stuck the longest, if one has been stuck for stallGrace, and gives its
// place to w. The call that ends it runs on its own: nothing that can be slow to return is called with the lock held or
// from the request that is waiting for the place, and the response's handler cannot return while it runs (see release).
func (p *upstreamPlaces) reclaim(w *writeWatch) bool {
	limit := monotonic() - int64(stallGrace)
	p.mu.Lock()
	if p.ending >= p.maxEnding {
		p.mu.Unlock()
		return false
	}
	var victim *writeWatch
	for h := range p.held {
		if s := h.since.Load(); s != 0 && s <= limit {
			limit, victim = s, h
		}
	}
	if victim == nil {
		p.mu.Unlock()
		return false
	}
	delete(p.held, victim)
	victim.ended = true
	p.ending++
	if w != nil {
		p.held[w] = struct{}{}
	}
	p.mu.Unlock()
	go victim.cut()
	return true
}
