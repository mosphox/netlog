package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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
	ID         int64      `json:"id"`
	Time       time.Time  `json:"time"`
	ClientAddr string     `json:"client_addr"`
	Scheme     string     `json:"scheme"`
	Method     string     `json:"method"`
	Host       string     `json:"host"`
	URL        string     `json:"url"`
	Upstream   string     `json:"upstream"` // upstream proxy used, or "direct"

	ReqProto   string     `json:"req_proto"`
	ReqHeaders []HeaderKV `json:"req_headers"`
	ReqBody    []byte     `json:"req_body"`

	Status      int        `json:"status"`
	RespProto   string     `json:"resp_proto"`
	RespHeaders []HeaderKV `json:"resp_headers"`
	RespBody    []byte     `json:"resp_body"`

	DurationMs int64  `json:"duration_ms"`
	Err        string `json:"err,omitempty"`
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

	file string // absolute path of the JSONL file holding the full record
	off  int64  // byte offset of the record's line
	len  int    // byte length of the record's line (without newline)
}

// logStore appends every transaction as one JSON line to a daily file and keeps
// an in-memory index for the web UI. Full records are read back on demand.
type logStore struct {
	dir string

	mu       sync.RWMutex
	entries  []*entry
	byID     map[int64]*entry
	nextID   int64
	curDay   string
	curFile  *os.File
	curPath  string
	curOff   int64
}

func newLogStore(dir string) (*logStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ls := &logStore{dir: dir, byID: make(map[int64]*entry)}
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
					e := &entry{
						ID: t.ID, Time: t.Time, ClientAddr: t.ClientAddr,
						Scheme: t.Scheme, Method: t.Method, Host: t.Host, URL: t.URL,
						Status: t.Status, ReqLen: len(t.ReqBody), RespLen: len(t.RespBody),
						DurationMs: t.DurationMs, Err: t.Err,
						file: f, off: off, len: len(trimmed),
					}
					ls.entries = append(ls.entries, e)
					ls.byID[t.ID] = e
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

	e := &entry{
		ID: t.ID, Time: t.Time, ClientAddr: t.ClientAddr,
		Scheme: t.Scheme, Method: t.Method, Host: t.Host, URL: t.URL,
		Status: t.Status, ReqLen: len(t.ReqBody), RespLen: len(t.RespBody),
		DurationMs: t.DurationMs, Err: t.Err,
		file: ls.curPath, off: off, len: len(line),
	}
	ls.entries = append(ls.entries, e)
	ls.byID[t.ID] = e
	return t.ID
}

// list returns index entries with ID > afterID, newest first, capped at limit.
func (ls *logStore) list(afterID int64, limit int) ([]*entry, int64) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	var out []*entry
	for i := len(ls.entries) - 1; i >= 0; i-- {
		e := ls.entries[i]
		if e.ID <= afterID {
			break
		}
		out = append(out, e)
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
	ls.mu.RUnlock()
	if !ok {
		return nil, false
	}
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
