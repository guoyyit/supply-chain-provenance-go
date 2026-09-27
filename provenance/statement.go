package provenance

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
)

// Statement 是一条针对某个制品的来源声明。
// 声明通过 PrevHash 与前一条声明链接成链。
type Statement struct {
	ArtifactID string            `json:"artifact_id"` // 制品标识
	Seq        uint64            `json:"seq"`         // 链内序号，从 0 开始
	Type       string            `json:"type"`        // 声明类型，如 build / test / sign
	Content    map[string]string `json:"content"`     // 声明内容（键值对）
	PrevHash   string            `json:"prev_hash"`   // 前一条声明的摘要，首条为 GenesisHash
	Hash       string            `json:"hash"`        // 本声明的内容摘要
}

// GenesisHash 是链首声明的 PrevHash 取值。
const GenesisHash = ""

// hashDomain 是摘要算法的域分隔前缀，标识编码版本。
const hashDomain = "SCP1\n"

// ComputeHash 计算声明内容摘要（不含 Hash 与 Seq 字段自身）。
// 算法：SHA-256( 域前缀 || 各字段的长度前缀规范化编码 )，输出小写十六进制。
// 相同内容必须得到稳定相同的摘要。
func ComputeHash(s Statement) string {
	sum := sha256.Sum256(canonicalEncoding(s))
	return hex.EncodeToString(sum[:])
}

// canonicalEncoding 返回声明内容的规范化编码，供摘要计算使用。
// 编码规则（所有字符串与字节均以 uvarint 长度前缀分隔，杜绝拼接歧义）：
//
//	"SCP1\n" || len(ArtifactID) || ArtifactID
//	         || len(Type)       || Type
//	         || len(PrevHash)   || PrevHash
//	         || len(Content 键数) || 按字典序排列的 (len(k)||k||len(v)||v) 序列
func canonicalEncoding(s Statement) []byte {
	var buf []byte
	buf = append(buf, hashDomain...)
	buf = appendLenPrefixed(buf, []byte(s.ArtifactID))
	buf = appendLenPrefixed(buf, []byte(s.Type))
	buf = appendLenPrefixed(buf, []byte(s.PrevHash))

	keys := make([]string, 0, len(s.Content))
	for k := range s.Content {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf = binary.AppendUvarint(buf, uint64(len(keys)))
	for _, k := range keys {
		buf = appendLenPrefixed(buf, []byte(k))
		buf = appendLenPrefixed(buf, []byte(s.Content[k]))
	}
	return buf
}

func appendLenPrefixed(buf, b []byte) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(b)))
	return append(buf, b...)
}
