// Package sign provides deterministic Ed25519 signing for ARV Proof OSS Canon v1.0.
//
// Canon rules (Sign v1.0):
// - Hash inputs are 64-char lowercase hex (32 bytes) representing SHA-256 digests.
// - Seed is 32 bytes encoded as 64-char lowercase hex.
// - Public key is 32 bytes encoded as 64-char lowercase hex.
// - Signature is 64 bytes encoded as 128-char lowercase hex.
// - All encoding is lowercase hex; inputs are validated strictly.
// - stdlib-only.
package sign

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

var (
	// ErrInvalidHex is returned when a hex string doesn't match required lowercase format.
	ErrInvalidHex = errors.New("invalid hex format")

	// ErrInvalidLength is returned when decoded bytes length is not expected.
	ErrInvalidLength = errors.New("invalid length")

	// ErrVerificationFailed is returned when signature verification fails.
	ErrVerificationFailed = errors.New("signature verification failed")
)

// Patterns for strict lowercase hex validation.
var (
	hex64Pattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)  // 32 bytes
	hex128Pattern = regexp.MustCompile(`^[a-f0-9]{128}$`) // 64 bytes
)

// ValidateHashHex validates a SHA-256 hash as 64 lowercase hex chars (32 bytes).
func ValidateHashHex(hashHex string) error {
	if !hex64Pattern.MatchString(hashHex) {
		return fmt.Errorf("%w: expected 64 lowercase hex chars, got %q", ErrInvalidHex, hashHex)
	}
	return nil
}

// ValidateSeedHex validates a seed as 64 lowercase hex chars (32 bytes).
func ValidateSeedHex(seedHex string) error {
	if !hex64Pattern.MatchString(seedHex) {
		return fmt.Errorf("%w: expected 64 lowercase hex chars, got %q", ErrInvalidHex, seedHex)
	}
	return nil
}

// ValidatePubKeyHex validates a public key as 64 lowercase hex chars (32 bytes).
func ValidatePubKeyHex(pubHex string) error {
	if !hex64Pattern.MatchString(pubHex) {
		return fmt.Errorf("%w: expected 64 lowercase hex chars, got %q", ErrInvalidHex, pubHex)
	}
	return nil
}

// ValidateSignatureHex validates a signature as 128 lowercase hex chars (64 bytes).
func ValidateSignatureHex(sigHex string) error {
	if !hex128Pattern.MatchString(sigHex) {
		return fmt.Errorf("%w: expected 128 lowercase hex chars, got %q", ErrInvalidHex, sigHex)
	}
	return nil
}

// DeriveKeyPairFromSeedHex derives (pubHex, privHex) from a 32-byte seed (hex).
// Note: privHex encodes the full ed25519.PrivateKey (64 bytes => 128 hex).
func DeriveKeyPairFromSeedHex(seedHex string) (pubHex string, privHex string, err error) {
	if err := ValidateSeedHex(seedHex); err != nil {
		return "", "", err
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode seed hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return "", "", fmt.Errorf("%w: seed bytes=%d expected=%d", ErrInvalidLength, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)     // 64 bytes
	pub := priv.Public().(ed25519.PublicKey) // 32 bytes
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// SignHashHex signs a 32-byte hash provided as 64-char lowercase hex using a seed (64 hex).
// Returns signatureHex (128 hex) and publicKeyHex (64 hex).
//
// Canon decision: message-to-sign is the RAW 32 bytes (decoded from hash hex),
// not the ASCII bytes of the hex string.
func SignHashHex(hashHex string, seedHex string) (sigHex string, pubHex string, err error) {
	if err := ValidateHashHex(hashHex); err != nil {
		return "", "", err
	}
	if err := ValidateSeedHex(seedHex); err != nil {
		return "", "", err
	}

	msg, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode hash hex: %w", err)
	}
	if len(msg) != 32 {
		return "", "", fmt.Errorf("%w: hash bytes=%d expected=32", ErrInvalidLength, len(msg))
	}

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode seed hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return "", "", fmt.Errorf("%w: seed bytes=%d expected=%d", ErrInvalidLength, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	sig := ed25519.Sign(priv, msg) // 64 bytes
	return hex.EncodeToString(sig), hex.EncodeToString(pub), nil
}

// VerifyHashHex verifies a signature over a 32-byte hash (64 hex) using a public key (64 hex).
//
// Returns (true, nil) if valid.
// Returns (false, ErrVerificationFailed) if syntactically valid inputs but signature mismatch.
// Returns (false, error) for malformed inputs.
func VerifyHashHex(hashHex string, sigHex string, pubHex string) (bool, error) {
	if err := ValidateHashHex(hashHex); err != nil {
		return false, err
	}
	if err := ValidateSignatureHex(sigHex); err != nil {
		return false, err
	}
	if err := ValidatePubKeyHex(pubHex); err != nil {
		return false, err
	}

	msg, err := hex.DecodeString(hashHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash hex: %w", err)
	}
	if len(msg) != 32 {
		return false, fmt.Errorf("%w: hash bytes=%d expected=32", ErrInvalidLength, len(msg))
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("%w: signature bytes=%d expected=%d", ErrInvalidLength, len(sig), ed25519.SignatureSize)
	}

	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode pubkey hex: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("%w: pubkey bytes=%d expected=%d", ErrInvalidLength, len(pub), ed25519.PublicKeySize)
	}

	ok := ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
	if !ok {
		return false, ErrVerificationFailed
	}
	return true, nil
}
