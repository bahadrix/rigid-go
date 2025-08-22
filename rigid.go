// Package rigid provides cryptographically secured ULIDs (Universally Unique Lexicographically Sortable Identifiers)
// with built-in HMAC-based integrity verification.
//
// Rigid generates tamper-proof, time-ordered unique identifiers that include cryptographic signatures
// to ensure integrity and prevent forgery. It supports optional metadata binding and configurable
// signature lengths for different security requirements.
//
// # Basic Usage
//
//	secretKey := []byte("your-secret-key")
//	r, err := rigid.NewRigid(secretKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate a secure ULID
//	rigidID, err := r.Generate()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate with metadata
//	rigidWithMetadata, err := r.Generate("user:alice:role:admin")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Verify integrity
//	result, err := r.Verify(rigidWithMetadata)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Valid: %t, Metadata: %s\n", result.Valid, result.Metadata)
//
// # Security Features
//
// - HMAC-SHA256 cryptographic signatures prevent tampering and forgery
// - Constant-time verification resists timing attacks
// - Configurable signature lengths (4-32 bytes) for security/size trade-offs
// - Thread-safe concurrent generation with monotonic entropy
//
// # ID Format
//
// Rigid IDs follow the format: ULID-SIGNATURE or ULID-SIGNATURE-METADATA
//
// Example: 01ARZ3NDEKTSV4RRFFQ69G5FAV-MFRGG2BA-user:session:12345
//
// # Compatibility
//
// This implementation is compatible with the Python rigid library when using
// the same secret key, signature length, and HMAC algorithm.
package rigid

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Error variables returned by rigid operations.
var (
	// ErrInvalidFormat indicates the rigid ID format is invalid.
	ErrInvalidFormat = errors.New("invalid rigid format")
	// ErrInvalidULID indicates the ULID component is malformed.
	ErrInvalidULID = errors.New("invalid ULID")
	// ErrIntegrityFailure indicates the signature verification failed.
	ErrIntegrityFailure = errors.New("integrity verification failed")
	// ErrEmptySecretKey indicates the provided secret key is empty or nil.
	ErrEmptySecretKey = errors.New("secret key cannot be empty")
	// ErrInvalidSigLength indicates the signature length is outside valid range.
	ErrInvalidSigLength = errors.New("signature length must be positive")
)

// Constants defining signature length constraints.
const (
	// DefaultSignatureLength is the default HMAC signature length in bytes.
	DefaultSignatureLength = 8
	// MinSignatureLength is the minimum allowed signature length in bytes.
	MinSignatureLength = 4
	// MaxSignatureLength is the maximum allowed signature length in bytes.
	MaxSignatureLength = 32
)

// Rigid is the main structure for generating and verifying cryptographically secured ULIDs.
// It maintains the secret key, signature configuration, and entropy source for ULID generation.
// All methods are thread-safe for concurrent use.
type Rigid struct {
	secretKey       []byte
	signatureLength int
	entropy         *ulid.MonotonicEntropy
	mu              sync.Mutex
}

// VerifyResult contains the results of a rigid ID verification operation.
type VerifyResult struct {
	// Valid indicates whether the rigid ID passed integrity verification.
	Valid bool
	// ULID contains the extracted ULID string.
	ULID string
	// Metadata contains the extracted metadata string, if any.
	Metadata string
}

// NewRigid creates a new Rigid instance with the provided secret key.
// The optional signatureLength parameter sets the HMAC signature length in bytes (4-32).
// If not provided, DefaultSignatureLength (8 bytes) is used.
// Returns an error if the secret key is empty or signature length is invalid.
func NewRigid(secretKey []byte, signatureLength ...int) (*Rigid, error) {
	if len(secretKey) == 0 {
		return nil, ErrEmptySecretKey
	}

	sigLen := DefaultSignatureLength
	if len(signatureLength) > 0 {
		sigLen = signatureLength[0]
		if sigLen < MinSignatureLength || sigLen > MaxSignatureLength {
			return nil, ErrInvalidSigLength
		}
	}

	entropy := ulid.Monotonic(rand.New(rand.NewSource(time.Now().UnixNano())), 0)

	r := &Rigid{
		secretKey:       make([]byte, len(secretKey)),
		signatureLength: sigLen,
		entropy:         entropy,
	}
	copy(r.secretKey, secretKey)

	return r, nil
}

// Generate creates a new cryptographically secured ULID with optional metadata.
// The optional metadata parameter will be cryptographically bound to the ID.
// Only the first metadata parameter is used if multiple are provided.
// Returns the generated rigid ID string or an error if generation fails.
func (r *Rigid) Generate(metadata ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	ulidObj, err := ulid.New(ulid.Timestamp(now), r.entropy)
	if err != nil {
		return "", err
	}

	ulidStr := ulidObj.String()

	var metadataStr string
	if len(metadata) > 0 {
		metadataStr = metadata[0]
	}

	signature := r.generateSignature(ulidStr, metadataStr)

	result := ulidStr + "-" + signature
	if metadataStr != "" {
		result += "-" + metadataStr
	}

	return result, nil
}

// Verify checks the integrity and authenticity of a rigid ID.
// Returns a VerifyResult containing validation status, extracted ULID, and metadata.
// Returns an error if the ID format is invalid or verification fails.
func (r *Rigid) Verify(secureULID string) (VerifyResult, error) {
	result := VerifyResult{}

	parts := strings.Split(secureULID, "-")
	if len(parts) < 2 {
		return result, ErrInvalidFormat
	}

	ulidStr := parts[0]
	signature := parts[1]
	var metadata string
	if len(parts) > 2 {
		metadata = strings.Join(parts[2:], "-")
	}

	if _, err := ulid.Parse(ulidStr); err != nil {
		return result, ErrInvalidULID
	}

	expectedSignature := r.generateSignature(ulidStr, metadata)

	if len(signature) != len(expectedSignature) {
		return result, ErrIntegrityFailure
	}

	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSignature)) != 1 {
		return result, ErrIntegrityFailure
	}

	result.Valid = true
	result.ULID = ulidStr
	result.Metadata = metadata

	return result, nil
}

// ExtractULID extracts and parses the ULID component from a rigid ID.
// Returns the parsed ULID object or an error if extraction fails.
func (r *Rigid) ExtractULID(secureULID string) (ulid.ULID, error) {
	var zeroULID ulid.ULID

	parts := strings.Split(secureULID, "-")
	if len(parts) < 2 {
		return zeroULID, ErrInvalidFormat
	}

	ulidObj, err := ulid.Parse(parts[0])
	if err != nil {
		return zeroULID, ErrInvalidULID
	}

	return ulidObj, nil
}

// ExtractTimestamp extracts the timestamp from the ULID component of a rigid ID.
// Returns the embedded timestamp or an error if extraction fails.
func (r *Rigid) ExtractTimestamp(secureULID string) (time.Time, error) {
	ulidObj, err := r.ExtractULID(secureULID)
	if err != nil {
		return time.Time{}, err
	}

	return ulid.Time(ulidObj.Time()), nil
}

func (r *Rigid) generateSignature(ulidStr, metadata string) string {
	h := hmac.New(sha256.New, r.secretKey)
	h.Write([]byte(ulidStr))
	if metadata != "" {
		h.Write([]byte(metadata))
	}

	sum := h.Sum(nil)
	truncated := sum[:r.signatureLength]

	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(truncated))
}
