package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HeaderKV is one header line, preserved in the exact order it was sent/received.
type HeaderKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Transaction is one fully-captured request/response pair. Bodies are stored in
// full (no truncation); binary-safe because JSON encodes []byte as base64.
type Transaction struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	ClientAddr string    `json:"client_addr"`
	Scheme     string    `json:"scheme"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	URL        string    `json:"url"`
	Upstream   string    `json:"upstream"` // upstream proxy used, or "direct"

	ReqProto   string     `json:"req_proto"`
	ReqHeaders []HeaderKV `json:"req_headers"`
	ReqBody    []byte     `json:"req_body"`

	Status      int        `json:"status"`
	RespProto   string     `json:"resp_proto"`
	RespHeaders []HeaderKV `json:"resp_headers"`
	RespBody    []byte     `json:"resp_body"`

	DurationMs int64  `json:"duration_ms"`
	Err        string `json:"err,omitempty"`
	Attempts   int    `json:"attempts,omitempty"` // upstream tries; >1 means retried on a fresh connection

	WSMessages []WSMessage `json:"ws_messages,omitempty"` // websocket traffic after the 101
	WSOpen     bool        `json:"ws_open,omitempty"`     // websocket still connected when this record was written
}

// WSMessage is one websocket message, reassembled from frames and unmasked.
// Data is decompressed when permessage-deflate was in use.
type WSMessage struct {
	Time       time.Time `json:"time"`
	FromClient bool      `json:"from_client"`
	Opcode     int       `json:"opcode"`
	Data       []byte    `json:"data"`
	Len        int       `json:"len"` // payload size on the wire (Data may be capped)
}

// entry is the lightweight in-memory index record used for listing and for
// locating the full transaction on disk.
type entry struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	ClientAddr string    `json:"client_addr"`
	Scheme     string    `json:"scheme"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	URL        string    `json:"url"`
	Status     int       `json:"status"`
	ReqLen     int       `json:"req_len"`
	RespLen    int       `json:"resp_len"`
	DurationMs int64     `json:"duration_ms"`
	Err        string    `json:"err,omitempty"`
	Attempts   int       `json:"attempts,omitempty"`
	WS         bool      `json:"ws,omitempty"`
	WSCount    int       `json:"ws_count,omitempty"`
	CT         string    `json:"ct,omitempty"` // response content-type, without parameters

	file string // absolute path of the JSONL file holding the full record
	off  int64  // byte offset of the record's line
	len  int    // byte length of the record's line (without newline)
}

// logStore appends every transaction as one JSON line to a daily file and keeps
// an in-memory index for the web UI. Full records are read back on demand.
type logStore struct {
	dir string

	mu      sync.RWMutex
	entries []*entry
	byID    map[int64]*entry
	live    map[int64]func() []WSMessage // open websockets
	nextID  int64
	curDay  string
	curFile *os.File
	curPath string
	curOff  int64
}

func newLogStore(dir string) (*logStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ls := &logStore{dir: dir, byID: make(map[int64]*entry), live: make(map[int64]func() []WSMessage)}
	ls.loadIndex()
	return ls, nil
}

// loadIndex scans existing JSONL files to rebuild the index (metadata + offsets)
// so history survives restarts. Bodies are not held in memory.
func (ls *logStore) loadIndex() {
	files, _ := filepath.Glob(filepath.Join(ls.dir, "*.jsonl"))
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		var off int64
		r := bufio.NewReaderSize(fh, 1<<20)
		for {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				trimmed := line
				if trimmed[len(trimmed)-1] == '\n' {
					trimmed = trimmed[:len(trimmed)-1]
				}
				var t Transaction
				if json.Unmarshal(trimmed, &t) == nil && t.ID != 0 {
					e := entryFor(&t, f, off, len(trimmed))
					if old, ok := ls.byID[t.ID]; ok {
						*old = *e // a later record of the same id supersedes (websocket close)
					} else {
						ls.entries = append(ls.entries, e)
						ls.byID[t.ID] = e
					}
					if t.ID >= ls.nextID {
						ls.nextID = t.ID + 1
					}
				}
			}
			off += int64(len(line))
			if err != nil {
				break
			}
		}
		fh.Close()
	}
	if ls.nextID == 0 {
		ls.nextID = 1
	}
}

func (ls *logStore) rotateIfNeeded() error {
	day := time.Now().Format("2006-01-02")
	if day == ls.curDay && ls.curFile != nil {
		return nil
	}
	if ls.curFile != nil {
		ls.curFile.Close()
	}
	path := filepath.Join(ls.dir, day+".jsonl")
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	info, _ := fh.Stat()
	ls.curFile = fh
	ls.curPath = path
	ls.curDay = day
	ls.curOff = info.Size()
	return nil
}

// add persists a transaction in full and indexes it. It assigns the ID.
func (ls *logStore) add(t *Transaction) int64 {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if err := ls.rotateIfNeeded(); err != nil {
		return 0
	}
	t.ID = ls.nextID
	ls.nextID++

	line, _ := json.Marshal(t)
	off := ls.curOff
	n, _ := ls.curFile.Write(append(line, '\n'))
	ls.curOff += int64(n)

	e := entryFor(t, ls.curPath, off, len(line))
	ls.entries = append(ls.entries, e)
	ls.byID[t.ID] = e
	return t.ID
}

// update rewrites a transaction that was already added (a websocket that has
// since closed). The log is append-only: the new record is appended and the
// index repointed, and on reload the later record wins.
func (ls *logStore) update(t *Transaction) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if err := ls.rotateIfNeeded(); err != nil {
		return
	}
	line, _ := json.Marshal(t)
	off := ls.curOff
	n, _ := ls.curFile.Write(append(line, '\n'))
	ls.curOff += int64(n)
	if old, ok := ls.byID[t.ID]; ok {
		*old = *entryFor(t, ls.curPath, off, len(line))
	}
}

// setLive registers (or with nil, removes) a snapshot function for an open
// websocket, so the detail view shows its messages before it closes.
func (ls *logStore) setLive(id int64, fn func() []WSMessage) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if fn == nil {
		delete(ls.live, id)
		return
	}
	ls.live[id] = fn
}

func entryFor(t *Transaction, file string, off int64, n int) *entry {
	return &entry{
		ID: t.ID, Time: t.Time, ClientAddr: t.ClientAddr,
		Scheme: t.Scheme, Method: t.Method, Host: t.Host, URL: t.URL,
		Status: t.Status, ReqLen: len(t.ReqBody), RespLen: len(t.RespBody),
		DurationMs: t.DurationMs, Err: t.Err, Attempts: t.Attempts,
		WS: t.WSOpen || len(t.WSMessages) > 0 || t.Status == 101, WSCount: len(t.WSMessages),
		CT:   strings.TrimSpace(strings.SplitN(headerValue(t.RespHeaders, "content-type"), ";", 2)[0]),
		file: file, off: off, len: n,
	}
}

// list returns index entries with afterID < ID < beforeID (beforeID 0 = no
// upper bound), newest first, capped at limit. Entries are copied so callers
// can read them without the lock.
func (ls *logStore) list(afterID, beforeID int64, limit int) ([]entry, int64) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	var out []entry
	for i := len(ls.entries) - 1; i >= 0; i-- {
		e := ls.entries[i]
		if e.ID <= afterID {
			break
		}
		if beforeID > 0 && e.ID >= beforeID {
			continue
		}
		out = append(out, *e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, ls.nextID - 1
}

func (ls *logStore) maxID() int64 {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.nextID - 1
}

func (ls *logStore) count() int {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return len(ls.entries)
}

// get reads and returns a full transaction by ID.
func (ls *logStore) get(id int64) (*Transaction, bool) {
	ls.mu.RLock()
	e, ok := ls.byID[id]
	var snap func() []WSMessage
	var where entry
	if ok {
		snap = ls.live[id]
		where = *e
	}
	ls.mu.RUnlock()
	if !ok {
		return nil, false
	}
	e = &where
	fh, err := os.Open(e.file)
	if err != nil {
		return nil, false
	}
	defer fh.Close()
	buf := make([]byte, e.len)
	if _, err := fh.ReadAt(buf, e.off); err != nil {
		return nil, false
	}
	var t Transaction
	if json.Unmarshal(buf, &t) != nil {
		return nil, false
	}
	if snap != nil {
		t.WSMessages = snap()
	}
	return &t, true
}

// allFull returns the full transactions currently in the index, oldest first.
func (ls *logStore) allFull() []*Transaction {
	ls.mu.RLock()
	ids := make([]int64, len(ls.entries))
	for i, e := range ls.entries {
		ids[i] = e.ID
	}
	ls.mu.RUnlock()

	out := make([]*Transaction, 0, len(ids))
	for _, id := range ids {
		if t, ok := ls.get(id); ok {
			out = append(out, t)
		}
	}
	return out
}

// clear drops the in-memory index and starts a fresh log file. Old files are
// left on disk (non-destructive); a new day file continues from a clean slate.
func (ls *logStore) clear() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.entries = nil
	ls.byID = make(map[int64]*entry)
	// keep nextID monotonic so IDs never collide with on-disk history
}
