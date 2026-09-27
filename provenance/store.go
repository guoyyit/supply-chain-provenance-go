package provenance

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Store persists committed statements, the active policy and evaluation
// results. Durability model:
//
//   - statements and results live in append-only WAL files; a record is
//     committed only after it is framed (magic + CRC32 + length), written and
//     fsynced, so a crash can leave at most one torn tail record;
//   - recovery scans each WAL, stops at the first corrupt/torn record and
//     truncates the file there, so partial appends never survive a restart;
//   - the policy file is replaced atomically (write tmp, fsync, rename,
//     fsync dir), so a crash yields either the old or the new policy, never a
//     mixture.
type Store struct {
	dir        string
	mu         sync.Mutex
	statements *wal
	results    *wal
}

const (
	statementsWAL = "statements.wal"
	resultsWAL    = "results.wal"
	policyFile    = "policy.json"

	recordMagic   uint32 = 0x50524f56 // "PROV"
	maxRecordSize        = 64 << 20   // 64 MiB sanity cap
	recordHeader         = 12         // magic(4) + crc(4) + length(4)
)

// OpenStore opens or creates a store rooted at dir and recovers committed
// state, discarding any torn tail left by a crash.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("provenance: create store dir: %w", err)
	}
	s := &Store{dir: dir}
	var err error
	if s.statements, err = openWAL(filepath.Join(dir, statementsWAL)); err != nil {
		return nil, err
	}
	if s.results, err = openWAL(filepath.Join(dir, resultsWAL)); err != nil {
		s.statements.close()
		return nil, err
	}
	return s, nil
}

// AppendStatement durably commits one statement. On return the record is
// fsynced and will survive a crash.
func (s *Store) AppendStatement(st Statement) error {
	payload, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("provenance: encode statement: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statements.append(payload)
}

// Statements replays all committed statements in append order.
func (s *Store) Statements() ([]Statement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payloads, err := s.statements.scan()
	if err != nil {
		return nil, err
	}
	out := make([]Statement, 0, len(payloads))
	for _, p := range payloads {
		var st Statement
		if err := json.Unmarshal(p, &st); err != nil {
			return nil, fmt.Errorf("provenance: decode statement record: %w", err)
		}
		out = append(out, st)
	}
	return out, nil
}

// SavePolicy atomically replaces the persisted policy.
func (s *Store) SavePolicy(p Policy) error {
	payload, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("provenance: encode policy: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteFile(filepath.Join(s.dir, policyFile), payload)
}

// LoadPolicy loads the persisted policy. A missing policy file yields an
// empty policy and no error.
func (s *Store) LoadPolicy() (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := os.ReadFile(filepath.Join(s.dir, policyFile))
	if errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("provenance: read policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		return Policy{}, fmt.Errorf("provenance: decode policy: %w", err)
	}
	return p, nil
}

// AppendResult durably commits one policy evaluation result.
func (s *Store) AppendResult(r PolicyResult) error {
	payload, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("provenance: encode result: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.results.append(payload)
}

// Results replays all committed evaluation results in append order.
func (s *Store) Results() ([]PolicyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payloads, err := s.results.scan()
	if err != nil {
		return nil, err
	}
	out := make([]PolicyResult, 0, len(payloads))
	for _, p := range payloads {
		var r PolicyResult
		if err := json.Unmarshal(p, &r); err != nil {
			return nil, fmt.Errorf("provenance: decode result record: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Close fsyncs and closes the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	if err := s.statements.close(); err != nil && first == nil {
		first = err
	}
	if err := s.results.close(); err != nil && first == nil {
		first = err
	}
	return first
}

// wal is an append-only, CRC-framed record log with torn-tail recovery.
type wal struct {
	path string
	f    *os.File
}

// openWAL opens the WAL at path and truncates any uncommitted torn tail.
func openWAL(path string) (*wal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("provenance: open wal %s: %w", path, err)
	}
	w := &wal{path: path, f: f}
	if err := w.truncateTornTail(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, fmt.Errorf("provenance: seek wal: %w", err)
	}
	return w, nil
}

// append frames, writes and fsyncs one record (the commit point).
func (w *wal) append(payload []byte) error {
	frame := make([]byte, recordHeader+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], recordMagic)
	binary.BigEndian.PutUint32(frame[4:8], crc32.ChecksumIEEE(payload))
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	copy(frame[recordHeader:], payload)
	if _, err := w.f.Write(frame); err != nil {
		return fmt.Errorf("provenance: write wal %s: %w", w.path, err)
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("provenance: fsync wal %s: %w", w.path, err)
	}
	return nil
}

// scan returns the payloads of all committed records in order.
func (w *wal) scan() ([][]byte, error) {
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("provenance: seek wal: %w", err)
	}
	var out [][]byte
	header := make([]byte, recordHeader)
	for {
		if _, err := io.ReadFull(w.f, header); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("provenance: read wal %s: %w", w.path, err)
		}
		if binary.BigEndian.Uint32(header[0:4]) != recordMagic {
			return nil, fmt.Errorf("provenance: wal %s corrupt: bad record magic", w.path)
		}
		crc := binary.BigEndian.Uint32(header[4:8])
		n := binary.BigEndian.Uint32(header[8:12])
		if n > maxRecordSize {
			return nil, fmt.Errorf("provenance: wal %s corrupt: record too large (%d bytes)", w.path, n)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.f, payload); err != nil {
			return nil, fmt.Errorf("provenance: read wal %s: %w", w.path, err)
		}
		if crc32.ChecksumIEEE(payload) != crc {
			return nil, fmt.Errorf("provenance: wal %s corrupt: crc mismatch", w.path)
		}
		out = append(out, payload)
	}
	if _, err := w.f.Seek(0, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("provenance: reseek wal: %w", err)
	}
	return out, nil
}

// truncateTornTail scans the WAL and cuts the file back to the end of the
// last fully committed record, discarding any partial append left by a crash.
func (w *wal) truncateTornTail() error {
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("provenance: seek wal: %w", err)
	}
	var goodOffset int64
	header := make([]byte, recordHeader)
	for {
		if _, err := io.ReadFull(w.f, header); err != nil {
			break // clean EOF or torn header: truncate here
		}
		if binary.BigEndian.Uint32(header[0:4]) != recordMagic {
			break // corrupt record start: truncate here
		}
		crc := binary.BigEndian.Uint32(header[4:8])
		n := binary.BigEndian.Uint32(header[8:12])
		if n > maxRecordSize {
			break
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.f, payload); err != nil {
			break // torn payload: truncate here
		}
		if crc32.ChecksumIEEE(payload) != crc {
			break // corrupt payload: truncate here
		}
		goodOffset += int64(recordHeader) + int64(n)
	}
	info, err := w.f.Stat()
	if err != nil {
		return fmt.Errorf("provenance: stat wal: %w", err)
	}
	if info.Size() != goodOffset {
		if err := w.f.Truncate(goodOffset); err != nil {
			return fmt.Errorf("provenance: truncate torn wal tail: %w", err)
		}
		if err := w.f.Sync(); err != nil {
			return fmt.Errorf("provenance: fsync truncated wal: %w", err)
		}
	}
	return nil
}

func (w *wal) close() error {
	if err := w.f.Sync(); err != nil {
		return err
	}
	return w.f.Close()
}

// atomicWriteFile writes payload to path via a temp file + rename, fsyncing
// both the file and the directory so the rename itself is durable.
func atomicWriteFile(path string, payload []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("provenance: create temp file: %w", err)
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("provenance: write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("provenance: fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("provenance: close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("provenance: rename policy file: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("provenance: open dir for fsync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("provenance: fsync dir: %w", err)
	}
	return nil
}
