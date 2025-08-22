package rigid

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	ErrInvalidFormat    = errors.New("invalid rigid format")
	ErrInvalidULID      = errors.New("invalid ULID")
	ErrIntegrityFailure = errors.New("integrity verification failed")
	ErrEmptySecretKey   = errors.New("secret key cannot be empty")
	ErrInvalidSigLength = errors.New("signature length must be positive")
)

const (
	DefaultSignatureLength = 8
	MinSignatureLength     = 4
	MaxSignatureLength     = 32
)

type Rigid struct {
	secretKey       []byte
	signatureLength int
	entropy         *ulid.MonotonicEntropy
}

type VerifyResult struct {
	Valid    bool
	ULID     string
	Metadata string
}

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

func (r *Rigid) Generate(metadata ...string) (string, error) {
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
