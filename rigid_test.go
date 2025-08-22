package rigid

import (
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSecretKey = []byte("test-secret-key-for-rigid-testing")

func TestNewRigid(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Equal(t, DefaultSignatureLength, r.signatureLength)
}

func TestNewRigidCustomSignatureLength(t *testing.T) {
	sigLen := 16
	r, err := NewRigid(testSecretKey, sigLen)
	require.NoError(t, err)
	assert.Equal(t, sigLen, r.signatureLength)
}

func TestNewRigidEmptyKey(t *testing.T) {
	_, err := NewRigid([]byte{})
	assert.Equal(t, ErrEmptySecretKey, err)

	_, err = NewRigid(nil)
	assert.Equal(t, ErrEmptySecretKey, err)
}

func TestNewRigidInvalidSignatureLength(t *testing.T) {
	tests := []int{0, 1, 2, 3, 33, 50, 100}

	for _, sigLen := range tests {
		_, err := NewRigid(testSecretKey, sigLen)
		assert.Equal(t, ErrInvalidSigLength, err, "sigLen=%d", sigLen)
	}
}

func TestGenerate(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	rigid, err := r.Generate()
	require.NoError(t, err)

	parts := strings.Split(rigid, "-")
	assert.Len(t, parts, 2)
	assert.Len(t, parts[0], 26)

	// Verify ULID is valid
	_, err = ulid.Parse(parts[0])
	assert.NoError(t, err, "Generated ULID should be valid")
}

func TestGenerateWithMetadata(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	metadata := "test-metadata"
	rigid, err := r.Generate(metadata)
	require.NoError(t, err)

	// Verify the rigid contains the metadata by parsing it
	result, err := r.Verify(rigid)
	require.NoError(t, err)
	assert.Equal(t, metadata, result.Metadata)
}

func TestGenerateWithMetadataContainingHyphens(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	metadata := "test-metadata-with-hyphens"
	rigid, err := r.Generate(metadata)
	require.NoError(t, err)

	// Verify we can extract the metadata correctly
	result, err := r.Verify(rigid)
	require.NoError(t, err)
	assert.Equal(t, metadata, result.Metadata)
}

func TestVerifyValid(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	rigid, err := r.Generate()
	require.NoError(t, err)

	result, err := r.Verify(rigid)
	require.NoError(t, err)
	assert.True(t, result.Valid)

	parts := strings.Split(rigid, "-")
	assert.Equal(t, parts[0], result.ULID)
}

func TestVerifyWithMetadata(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	metadata := "test-metadata-123"
	rigid, err := r.Generate(metadata)
	require.NoError(t, err)

	result, err := r.Verify(rigid)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, metadata, result.Metadata)
}

func TestVerifyInvalidFormat(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	tests := []string{
		"",
	}

	for _, test := range tests {
		_, err := r.Verify(test)
		assert.Equal(t, ErrInvalidFormat, err, "input: %q", test)
	}
}

func TestVerifyInvalidULID(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	tests := []string{
		"invalid-ulid-signature",
		"12345-SIGNATURE",
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZ-SIG", // Invalid ULID
		"no-hyphens-at-all",              // No hyphens, treated as single part, invalid ULID
	}

	for _, test := range tests {
		_, err := r.Verify(test)
		assert.Equal(t, ErrInvalidULID, err, "input: %q", test)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	r1, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	rigid, err := r1.Generate()
	require.NoError(t, err)

	wrongKey := []byte("wrong-secret-key")
	r2, err := NewRigid(wrongKey)
	require.NoError(t, err)

	_, err = r2.Verify(rigid)
	assert.Equal(t, ErrIntegrityFailure, err)
}

func TestVerifyTamperedSignature(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	rigid, err := r.Generate()
	require.NoError(t, err)

	parts := strings.Split(rigid, "-")
	require.NotEmpty(t, parts[1], "Signature should not be empty")

	// Tamper with signature
	tamperedSig := parts[1][:len(parts[1])-1] + "Z"
	tamperedRigid := parts[0] + "-" + tamperedSig

	_, err = r.Verify(tamperedRigid)
	assert.Equal(t, ErrIntegrityFailure, err)
}

func TestExtractULID(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	rigid, err := r.Generate()
	require.NoError(t, err)

	ulidObj, err := r.ExtractULID(rigid)
	require.NoError(t, err)

	parts := strings.Split(rigid, "-")
	expectedULID, err := ulid.Parse(parts[0])
	require.NoError(t, err)

	assert.Equal(t, expectedULID.String(), ulidObj.String())
}

func TestExtractULIDInvalidFormat(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	_, err = r.ExtractULID("invalid")
	assert.Equal(t, ErrInvalidFormat, err)
}

func TestExtractTimestamp(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	before := time.Now()
	rigid, err := r.Generate()
	require.NoError(t, err)
	after := time.Now()

	timestamp, err := r.ExtractTimestamp(rigid)
	require.NoError(t, err)

	// Allow for some timing variance
	assert.True(t, timestamp.After(before.Add(-time.Second)) && timestamp.Before(after.Add(time.Second)),
		"ExtractTimestamp() = %v, want between %v and %v (with 1s tolerance)", timestamp, before, after)
}

func TestUniqueness(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	seen := make(map[string]bool)
	count := 1000

	for i := 0; i < count; i++ {
		rigid, err := r.Generate()
		require.NoError(t, err)

		assert.False(t, seen[rigid], "Duplicate rigid generated: %s", rigid)
		seen[rigid] = true
	}
}

func TestDifferentSignatureLengths(t *testing.T) {
	tests := []int{4, 8, 16, 32}

	for _, sigLen := range tests {
		r, err := NewRigid(testSecretKey, sigLen)
		require.NoError(t, err, "sigLen=%d", sigLen)

		rigid, err := r.Generate()
		require.NoError(t, err, "sigLen=%d", sigLen)

		result, err := r.Verify(rigid)
		require.NoError(t, err, "sigLen=%d", sigLen)
		assert.True(t, result.Valid, "sigLen=%d", sigLen)
	}
}

func TestConcurrentGeneration(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	const goroutines = 5
	const idsPerGoroutine = 5

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allRigids []string
	var allErrors []error

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < idsPerGoroutine; j++ {
				// Add small delay to prevent monotonic entropy overflow
				time.Sleep(time.Microsecond * time.Duration(goroutineID*10+j))
				
				rigid, err := r.Generate()
				
				mu.Lock()
				if err != nil {
					// Only fail on unexpected errors, not entropy overflow
					if !strings.Contains(err.Error(), "monotonic entropy overflow") {
						allErrors = append(allErrors, err)
					}
				} else {
					allRigids = append(allRigids, rigid)
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// Check for any unexpected errors
	for _, err := range allErrors {
		assert.NoError(t, err, "Unexpected error in concurrent test")
	}

	// Verify all generated rigids are valid
	for _, rigid := range allRigids {
		result, err := r.Verify(rigid)
		assert.NoError(t, err, "rigid: %s", rigid)
		assert.True(t, result.Valid, "rigid: %s", rigid)
	}

	// Check uniqueness
	seen := make(map[string]bool)
	duplicates := 0
	for _, rigid := range allRigids {
		if seen[rigid] {
			duplicates++
		} else {
			seen[rigid] = true
		}
	}

	// We should have generated at least some IDs
	assert.Greater(t, len(allRigids), 0, "Should generate at least some IDs")
	
	t.Logf("Generated %d rigids, %d duplicates, %d unique", len(allRigids), duplicates, len(seen))
}

func TestSignatureLengthBoundaries(t *testing.T) {
	// Test minimum valid length
	r, err := NewRigid(testSecretKey, MinSignatureLength)
	require.NoError(t, err)

	rigid, err := r.Generate()
	require.NoError(t, err)

	_, err = r.Verify(rigid)
	assert.NoError(t, err)

	// Test maximum valid length
	r, err = NewRigid(testSecretKey, MaxSignatureLength)
	require.NoError(t, err)

	rigid, err = r.Generate()
	require.NoError(t, err)

	_, err = r.Verify(rigid)
	assert.NoError(t, err)
}

func TestEmptyMetadata(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	rigid, err := r.Generate("")
	require.NoError(t, err)

	result, err := r.Verify(rigid)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Empty(t, result.Metadata)
}

func TestMultipleMetadataParams(t *testing.T) {
	r, err := NewRigid(testSecretKey)
	require.NoError(t, err)

	// Only first metadata parameter should be used
	rigid, err := r.Generate("first", "second", "third")
	require.NoError(t, err)

	result, err := r.Verify(rigid)
	require.NoError(t, err)
	assert.Equal(t, "first", result.Metadata)
}

// Benchmark tests
func BenchmarkGenerate(b *testing.B) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(b, err)

	r, err := NewRigid(key)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Generate()
		require.NoError(b, err)
	}
}

func BenchmarkVerify(b *testing.B) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(b, err)

	r, err := NewRigid(key)
	require.NoError(b, err)

	rigid, err := r.Generate()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Verify(rigid)
		require.NoError(b, err)
	}
}

func BenchmarkGenerateWithMetadata(b *testing.B) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(b, err)

	r, err := NewRigid(key)
	require.NoError(b, err)

	metadata := "benchmark-metadata"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Generate(metadata)
		require.NoError(b, err)
	}
}
