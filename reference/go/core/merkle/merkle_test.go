package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// makeLeaves hashes arbitrary strings into canonical 64-char lowercase hex leaves.
// This matches the Merkle module expectation: leaves are already SHA-256 hex strings.
func makeLeaves(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		sum := sha256.Sum256([]byte(v))
		out[i] = hex.EncodeToString(sum[:])
	}
	return out
}

func TestBuildRoot_EmptyLeaves(t *testing.T) {
	_, err := BuildRoot(nil)
	if err == nil {
		t.Fatalf("expected error for empty leaves")
	}
	if !strings.Contains(err.Error(), ErrEmptyLeaves.Error()) {
		t.Fatalf("expected ErrEmptyLeaves, got %v", err)
	}
}

func TestBuildRoot_SingleLeafIsRoot(t *testing.T) {
	leaves := makeLeaves([]string{"A"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}
	if root != leaves[0] {
		t.Fatalf("expected root == leaf, got %s want %s", root, leaves[0])
	}
}

func TestBuildRoot_InvalidLeafFormat(t *testing.T) {
	leaves := []string{"zzz"} // invalid
	_, err := BuildRoot(leaves)
	if err == nil {
		t.Fatalf("expected error for invalid leaf")
	}
	if !strings.Contains(err.Error(), ErrInvalidLeafFormat.Error()) {
		t.Fatalf("expected ErrInvalidLeafFormat, got %v", err)
	}
}

func TestBuildProof_IndexOutOfBounds(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B"})
	_, _, err := BuildProof(leaves, 2)
	if err == nil {
		t.Fatalf("expected error for out of bounds index")
	}
	if !strings.Contains(err.Error(), ErrInvalidIndex.Error()) {
		t.Fatalf("expected ErrInvalidIndex, got %v", err)
	}
}

func TestVerifyProof_RoundTrip_AllLeaves(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B", "C", "D", "E"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	for i := range leaves {
		proof, prRoot, err := BuildProof(leaves, i)
		if err != nil {
			t.Fatalf("BuildProof(%d) error: %v", i, err)
		}
		if prRoot != root {
			t.Fatalf("BuildProof root mismatch: got %s want %s", prRoot, root)
		}

		ok, err := VerifyProof(leaves[i], i, len(leaves), proof, root)
		if err != nil {
			t.Fatalf("VerifyProof(%d) error: %v", i, err)
		}
		if !ok {
			t.Fatalf("VerifyProof(%d) expected ok=true", i)
		}
	}
}

func TestVerifyProof_EmptyProofWhenTotalLeavesGreaterThanOne(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	ok, err := VerifyProof(leaves[0], 0, len(leaves), []ProofNode{}, root)
	if err == nil {
		t.Fatalf("expected error for empty proof when totalLeaves > 1; got ok=%v err=nil", ok)
	}
	if ok {
		t.Fatalf("expected ok=false; got ok=true err=%v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidProof.Error()) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProof_InvalidProofHash(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	proof, _, err := BuildProof(leaves, 0)
	if err != nil {
		t.Fatalf("BuildProof error: %v", err)
	}
	if len(proof) == 0 {
		t.Fatalf("expected non-empty proof")
	}

	proof[0].Hash = "zzz" // invalid format
	ok, err := VerifyProof(leaves[0], 0, len(leaves), proof, root)
	if err == nil {
		t.Fatalf("expected error for invalid proof hash; got ok=%v err=nil", ok)
	}
	if ok {
		t.Fatalf("expected ok=false; got ok=true err=%v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidLeafFormat.Error()) {
		t.Fatalf("expected ErrInvalidLeafFormat, got %v", err)
	}
}

func TestVerifyProof_SingleLeafWithNonEmptyProof(t *testing.T) {
	leaves := makeLeaves([]string{"A"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	proof := []ProofNode{{Hash: leaves[0], Position: "left"}}
	ok, err := VerifyProof(leaves[0], 0, len(leaves), proof, root)
	if err == nil {
		t.Fatalf("expected error for non-empty proof when totalLeaves == 1; got ok=%v err=nil", ok)
	}
	if ok {
		t.Fatalf("expected ok=false; got ok=true err=%v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidProof.Error()) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

// Strict binding tests

func TestVerifyProof_InvalidPositionRejected(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B", "C", "D"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	idx := 2
	proof, _, err := BuildProof(leaves, idx)
	if err != nil {
		t.Fatalf("BuildProof error: %v", err)
	}
	if len(proof) == 0 {
		t.Fatalf("expected non-empty proof")
	}

	// Flip the first position
	if proof[0].Position == "left" {
		proof[0].Position = "right"
	} else {
		proof[0].Position = "left"
	}

	ok, err := VerifyProof(leaves[idx], idx, len(leaves), proof, root)
	if err == nil {
		t.Fatalf("expected error for invalid position; got ok=%v err=nil", ok)
	}
	if ok {
		t.Fatalf("expected ok=false; got ok=true err=%v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidProof.Error()) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProof_WrongLengthRejected(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B", "C", "D"})
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	idx := 1
	proof, _, err := BuildProof(leaves, idx)
	if err != nil {
		t.Fatalf("BuildProof error: %v", err)
	}
	if len(proof) < 2 {
		t.Fatalf("expected proof length >= 2 for 4 leaves, got %d", len(proof))
	}

	// Remove one step => wrong length
	proof = proof[:len(proof)-1]

	ok, err := VerifyProof(leaves[idx], idx, len(leaves), proof, root)
	if err == nil {
		t.Fatalf("expected error for wrong proof length; got ok=%v err=nil", ok)
	}
	if ok {
		t.Fatalf("expected ok=false; got ok=true err=%v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidProof.Error()) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProof_OddDuplicationRuleBound(t *testing.T) {
	leaves := makeLeaves([]string{"A", "B", "C"}) // odd
	root, err := BuildRoot(leaves)
	if err != nil {
		t.Fatalf("BuildRoot error: %v", err)
	}

	// last index forces duplication at first level
	idx := 2
	proof, _, err := BuildProof(leaves, idx)
	if err != nil {
		t.Fatalf("BuildProof error: %v", err)
	}
	if len(proof) == 0 {
		t.Fatalf("expected non-empty proof")
	}

	// First level sibling should be self; corrupt to another valid leaf
	proof[0].Hash = leaves[1]

	ok, err := VerifyProof(leaves[idx], idx, len(leaves), proof, root)
	if err == nil {
		t.Fatalf("expected error for odd-duplication violation; got ok=%v err=nil", ok)
	}
	if ok {
		t.Fatalf("expected ok=false; got ok=true err=%v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidProof.Error()) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}
