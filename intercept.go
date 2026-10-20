package main

import (
	"strings"
	"sync"
	"time"
)

// interceptHoldMax is how long a held request waits for a decision before it
// is forwarded unchanged, so a forgotten browser tab cannot hang forever.
const interceptHoldMax = 10 * time.Minute

type interceptDecision struct {
	drop bool
	edit *sendRequest // nil = forward unchanged
}

// heldRequest is a request paused in intercept, waiting for the operator.
type heldRequest struct {
	ID       int64      `json:"id"`
	Time     time.Time  `json:"time"`
	Client   string     `json:"client"`
	Method   string     `json:"method"`
	URL      string     `json:"url"`
	Headers  []HeaderKV `json:"headers"`
	Body     []byte     `json:"body"`
	Proto    string     `json:"proto"`
	decision chan interceptDecision
}

// interceptQueue holds requests until the web UI forwards, edits or drops them.
type interceptQueue struct {
	mu     sync.Mutex
	nextID int64
	held   []*heldRequest
}

func newInterceptQueue() *interceptQueue { return &interceptQueue{} }

// hold blocks until the operator decides what to do with the request.
func (q *interceptQueue) hold(txn *Transaction) interceptDecision {
	q.mu.Lock()
	q.nextID++
	h := &heldRequest{ID: q.nextID, Time: time.Now(), Client: txn.ClientAddr, Method: txn.Method, URL: txn.URL,
		Headers: txn.ReqHeaders, Body: txn.ReqBody, Proto: txn.ReqProto, decision: make(chan interceptDecision, 1)}
	q.held = append(q.held, h)
	q.mu.Unlock()

	var d interceptDecision
	select {
	case d = <-h.decision:
	case <-time.After(interceptHoldMax):
		q.remove(h.ID)
	}
	return d
}

func (q *interceptQueue) remove(id int64) *heldRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, h := range q.held {
		if h.ID == id {
			q.held = append(q.held[:i:i], q.held[i+1:]...)
			return h
		}
	}
	return nil
}

func (q *interceptQueue) list() []*heldRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]*heldRequest(nil), q.held...)
}

// decide resolves one held request. It reports false if it is no longer held.
func (q *interceptQueue) decide(id int64, d interceptDecision) bool {
	h := q.remove(id)
	if h == nil {
		return false
	}
	h.decision <- d
	return true
}

// forwardAll releases every held request unchanged (interception turned off).
func (q *interceptQueue) forwardAll() {
	q.mu.Lock()
	held := q.held
	q.held = nil
	q.mu.Unlock()
	for _, h := range held {
		h.decision <- interceptDecision{}
	}
}

// interceptMatches applies the intercept filter to a host: space-separated
// substrings, any of which must match; a leading "-" excludes. An empty
// filter (or one with only exclusions) matches every other host.
func interceptMatches(filter, host string) bool {
	host = strings.ToLower(host)
	include, any := false, false
	for _, t := range strings.Fields(strings.ToLower(filter)) {
		if strings.HasPrefix(t, "-") {
			if strings.Contains(host, t[1:]) {
				return false
			}
			continue
		}
		any = true
		if strings.Contains(host, t) {
			include = true
		}
	}
	return include || !any
}
