package main

import (
	"fmt"
	"log"

	"github.com/bahadrix/rigid-go"
)

func main() {
	secretKey := []byte("your-secret-key-here")

	fmt.Println("=== Rigid ULID Examples ===\n")

	r, err := rigid.NewRigid(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("1. Generating Rigid ULIDs:")
	for i := 0; i < 3; i++ {
		rigidID, err := r.Generate()
		if err != nil {
			log.Fatal(err)
		}

		timestamp, err := r.ExtractTimestamp(rigidID)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("   Rigid ID %d: %s\n", i+1, rigidID)
		fmt.Printf("   Timestamp: %s\n\n", timestamp.Format("2006-01-02 15:04:05.000"))
	}

	fmt.Println("2. Generating with metadata:")
	metadata := "user-profile"
	rigidWithMetadata, err := r.Generate(metadata)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("   With metadata: %s\n", rigidWithMetadata)

	result, err := r.Verify(rigidWithMetadata)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("   Valid: %t\n", result.Valid)
	fmt.Printf("   ULID: %s\n", result.ULID)
	fmt.Printf("   Metadata: %s\n\n", result.Metadata)

	fmt.Println("3. Verification and integrity:")
	rigidID, err := r.Generate()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("   Original: %s\n", rigidID)

	result, err = r.Verify(rigidID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("   Verification: %t\n\n", result.Valid)

	fmt.Println("4. Tamper detection (wrong key):")
	wrongKey := []byte("wrong-key")
	r2, err := rigid.NewRigid(wrongKey)
	if err != nil {
		log.Fatal(err)
	}

	_, err = r2.Verify(rigidID)
	if err != nil {
		fmt.Printf("   Error (expected): %s\n", err)
	}
}
