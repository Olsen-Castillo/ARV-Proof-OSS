package sign

import (
	"errors"
	"testing"
)

func TestDeriveKeyPairFromSeedHex_Deterministic(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	pub1, priv1, err := DeriveKeyPairFromSeedHex(seed)
	if err != nil {
		t.Fatalf("DeriveKeyPairFromSeedHex error: %v", err)
	}

	pub2, priv2, err := DeriveKeyPairFromSeedHex(seed)
	if err != nil {
		t.Fatalf("DeriveKeyPairFromSeedHex error: %v", err)
	}

	if pub1 != pub2 || priv1 != priv2 {
		t.Fatalf("non-deterministic derivation: pub1=%s pub2=%s priv1=%s priv2=%s", pub1, pub2, priv1, priv2)
	}

	// Format sanity
	if err := ValidatePubKeyHex(pub1); err != nil {
		t.Fatalf("pub key not canonical hex: %v", err)
	}
	if err := ValidateSignatureHex(priv1); err != nil {
		t.Logf("NOTE: priv key is 128 hex; ValidateSignatureHex accepts it (format-only check, not semantic priv validator)")
	}
	if len(priv1) != 128 {
		t.Fatalf("expected priv hex length 128, got %d", len(priv1))
	}
}

func TestSignAndVerifyHashHex_Success(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	// Example 32-byte hash (64 hex)
	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	sigHex, pubHex, err := SignHashHex(hashHex, seed)
	if err != nil {
		t.Fatalf("SignHashHex error: %v", err)
	}

	if err := ValidateSignatureHex(sigHex); err != nil {
		t.Fatalf("signature not canonical hex: %v", err)
	}
	if err := ValidatePubKeyHex(pubHex); err != nil {
		t.Fatalf("pubkey not canonical hex: %v", err)
	}

	ok, err := VerifyHashHex(hashHex, sigHex, pubHex)
	if err != nil {
		t.Fatalf("VerifyHashHex unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
}

func TestVerifyHashHex_FailsOnMismatch(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sigHex, pubHex, err := SignHashHex(hashHex, seed)
	if err != nil {
		t.Fatalf("SignHashHex error: %v", err)
	}

	// Different hash must fail
	otherHash := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // SHA-256("abc")
	ok, err := VerifyHashHex(otherHash, sigHex, pubHex)
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed, got ok=%v err=%v", ok, err)
	}
	if ok {
		t.Fatalf("expected ok=false")
	}
}

func TestSignHashHex_InvalidInputs(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	t.Run("invalid hash hex", func(t *testing.T) {
		_, _, err := SignHashHex("ZZZ", seed)
		if err == nil || !errors.Is(err, ErrInvalidHex) {
			t.Fatalf("expected ErrInvalidHex, got %v", err)
		}
	})

	t.Run("invalid seed hex", func(t *testing.T) {
		_, _, err := SignHashHex(hashHex, "abc")
		if err == nil || !errors.Is(err, ErrInvalidHex) {
			t.Fatalf("expected ErrInvalidHex, got %v", err)
		}
	})

	t.Run("uppercase rejected", func(t *testing.T) {
		_, _, err := SignHashHex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", seed)
		if err == nil || !errors.Is(err, ErrInvalidHex) {
			t.Fatalf("expected ErrInvalidHex, got %v", err)
		}
	})
}

func TestVerifyHashHex_MalformedSignatureOrKey(t *testing.T) {
	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	t.Run("invalid signature hex format", func(t *testing.T) {
		ok, err := VerifyHashHex(hashHex, "zzz", "00")
		if err == nil {
			t.Fatalf("expected error, got ok=%v err=nil", ok)
		}
		if ok {
			t.Fatalf("expected ok=false")
		}
	})

	t.Run("invalid pubkey hex format", func(t *testing.T) {
		// 128 hex signature placeholder, but pub is invalid
		sig := "00"
		for len(sig) < 128 {
			sig += "0"
		}
		ok, err := VerifyHashHex(hashHex, sig, "zzz")
		if err == nil {
			t.Fatalf("expected error, got ok=%v err=nil", ok)
		}
		if ok {
			t.Fatalf("expected ok=false")
		}
	})
}
