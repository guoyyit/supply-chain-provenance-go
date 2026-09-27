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
)

// 记录格式（ statements.log ，仅追加）：
//
//	[4 字节大端 payload 长度][payload(JSON 编码的 Statement)][4 字节 CRC32(payload)]
//
// 崩溃恢复：顺序扫描，遇到长度前缀不完整、payload 不完整或 CRC 不匹配时，
// 将该偏移视为撕裂写入的尾部并截断，已提交的前缀记录不受影响。
const (
	lenSize  = 4
	crcSize  = 4
	frameMax = 1 << 20 // 单条记录 payload 上限 1MiB，防御长度前缀损坏
)

const (
	statementsFile = "statements.log"
	policiesFile   = "policies.json"
)

// Store 提供声明的持久化存储与崩溃恢复。
type Store struct {
	dir string
	log *os.File
	off int64 // 当前日志写入偏移
}

// OpenStore 打开（必要时创建）存储目录，并执行崩溃恢复：
// 截断日志中未完成的尾部写入，保证不留部分写入。
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, statementsFile)

	// 先以只读方式扫描，确定最后一个完好记录的偏移。
	good, err := scanLog(path)
	if err != nil {
		return nil, err
	}
	// 截断撕裂尾部（文件尚不存在时无需截断）。
	if _, statErr := os.Stat(path); statErr == nil {
		if err := os.Truncate(path, good); err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, log: f, off: good}, nil
}

// scanLog 返回日志中最后一个完好记录的结束偏移。
func scanLog(path string) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var off int64
	hdr := make([]byte, lenSize)
	for {
		if _, err := io.ReadFull(f, hdr); err != nil {
			return off, nil // 长度前缀读不完整：到达完好前缀末尾
		}
		n := binary.BigEndian.Uint32(hdr)
		if n == 0 || n > frameMax {
			return off, nil // 长度前缀损坏
		}
		payload := make([]byte, n+crcSize)
		if _, err := io.ReadFull(f, payload); err != nil {
			return off, nil // payload 或 CRC 不完整
		}
		if crc32.ChecksumIEEE(payload[:n]) != binary.BigEndian.Uint32(payload[n:]) {
			return off, nil // CRC 不匹配：撕裂或损坏
		}
		off += int64(lenSize) + int64(n) + crcSize
	}
}

// Append 持久化一条声明。单次 write 系统调用保证记录不会与其他写入交织；
// 进程崩溃时，未完整落盘的尾部记录会在下次 OpenStore 时被截断。
func (s *Store) Append(st Statement) error {
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if len(payload) > frameMax {
		return fmt.Errorf("statement payload too large: %d bytes", len(payload))
	}
	frame := make([]byte, 0, lenSize+len(payload)+crcSize)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	frame = binary.BigEndian.AppendUint32(frame, crc32.ChecksumIEEE(payload))
	if _, err := s.log.Write(frame); err != nil {
		return err
	}
	s.off += int64(len(frame))
	return nil
}

// Sync 将日志刷到持久介质（供需要抗操作系统崩溃的调用方使用）。
func (s *Store) Sync() error {
	return s.log.Sync()
}

// LoadAll 读取全部已提交声明（恢复时已截断未完成尾部，这里读到的一定完好）。
func (s *Store) LoadAll() ([]Statement, error) {
	path := filepath.Join(s.dir, statementsFile)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Statement
	for {
		hdr := make([]byte, lenSize)
		if _, err := io.ReadFull(f, hdr); err != nil {
			return out, nil
		}
		n := binary.BigEndian.Uint32(hdr)
		if n == 0 || n > frameMax {
			return out, nil
		}
		payload := make([]byte, n+crcSize)
		if _, err := io.ReadFull(f, payload); err != nil {
			return out, nil
		}
		if crc32.ChecksumIEEE(payload[:n]) != binary.BigEndian.Uint32(payload[n:]) {
			return out, nil
		}
		var st Statement
		if err := json.Unmarshal(payload[:n], &st); err != nil {
			return out, nil
		}
		out = append(out, st)
	}
}

// SavePolicies 原子持久化策略配置（写临时文件后 rename，崩溃不留半写文件）。
func (s *Store) SavePolicies(policies map[string]Policy) error {
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, policiesFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, policiesFile))
}

// LoadPolicies 读取策略配置；不存在时返回空表。
func (s *Store) LoadPolicies() (map[string]Policy, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, policiesFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Policy{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]Policy{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Close 关闭存储。
func (s *Store) Close() error {
	return s.log.Close()
}
