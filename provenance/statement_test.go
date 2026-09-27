package provenance

import (
	"encoding/hex"
	"testing"
)

func TestComputeHashStable(t *testing.T) {
	s1 := Statement{
		ArtifactID: "artifact-1",
		Type:       "build",
		Content:    map[string]string{"builder": "ci", "commit": "abc"},
		PrevHash:   GenesisHash,
	}
	s2 := s1
	// 内容键顺序不同（map 迭代顺序随机），摘要必须一致。
	s2.Content = map[string]string{"commit": "abc", "builder": "ci"}
	h1, h2 := ComputeHash(s1), ComputeHash(s2)
	if h1 != h2 {
		t.Fatalf("hash unstable across content key order: %s != %s", h1, h2)
	}
	if len(h1) != hex.EncodedLen(32) {
		t.Fatalf("hash should be 64 hex chars, got %d (%q)", len(h1), h1)
	}
	if ComputeHash(s1) != h1 {
		t.Fatal("hash not stable across repeated calls")
	}
}

func TestComputeHashSensitiveToFields(t *testing.T) {
	base := Statement{ArtifactID: "a", Type: "build", Content: map[string]string{"k": "v"}, PrevHash: GenesisHash}
	baseHash := ComputeHash(base)

	changes := map[string]Statement{
		"artifact id": {ArtifactID: "b", Type: "build", Content: map[string]string{"k": "v"}, PrevHash: GenesisHash},
		"type":        {ArtifactID: "a", Type: "test", Content: map[string]string{"k": "v"}, PrevHash: GenesisHash},
		"content key": {ArtifactID: "a", Type: "build", Content: map[string]string{"k2": "v"}, PrevHash: GenesisHash},
		"content val": {ArtifactID: "a", Type: "build", Content: map[string]string{"k": "w"}, PrevHash: GenesisHash},
		"prev hash":   {ArtifactID: "a", Type: "build", Content: map[string]string{"k": "v"}, PrevHash: "deadbeef"},
		"extra key":   {ArtifactID: "a", Type: "build", Content: map[string]string{"k": "v", "x": "y"}, PrevHash: GenesisHash},
	}
	for name, st := range changes {
		if ComputeHash(st) == baseHash {
			t.Errorf("hash collision after changing %s", name)
		}
	}
}

func TestComputeHashLengthPrefixNoAmbiguity(t *testing.T) {
	// "ab"/"c" 与 "a"/"bc" 的裸拼接相同，但长度前缀编码必须区分。
	s1 := Statement{ArtifactID: "ab", Type: "c", Content: map[string]string{}, PrevHash: GenesisHash}
	s2 := Statement{ArtifactID: "a", Type: "bc", Content: map[string]string{}, PrevHash: GenesisHash}
	if ComputeHash(s1) == ComputeHash(s2) {
		t.Fatal("length-prefixed encoding failed to distinguish different field splits")
	}
}
