package main

import (
	"fmt"
	"log"
	"time"

	"rigid-go"
)

type UserService struct {
	rigid *rigid.Rigid
}

func NewUserService(secretKey []byte) *UserService {
	r, err := rigid.NewRigid(secretKey, 16)
	if err != nil {
		log.Fatal(err)
	}
	
	return &UserService{rigid: r}
}

func (s *UserService) CreateUser(username, role string) string {
	metadata := fmt.Sprintf("user:%s:role:%s", username, role)
	userID, err := s.rigid.Generate(metadata)
	if err != nil {
		log.Fatal(err)
	}
	return userID
}

func (s *UserService) ValidateUser(userID string) (bool, string, string, error) {
	result, err := s.rigid.Verify(userID)
	if err != nil {
		return false, "", "", err
	}
	
	if !result.Valid {
		return false, "", "", nil
	}
	
	timestamp, err := s.rigid.ExtractTimestamp(userID)
	if err != nil {
		return false, "", "", err
	}
	
	return true, result.Metadata, timestamp.Format("2006-01-02 15:04:05"), nil
}

type SessionManager struct {
	rigid *rigid.Rigid
}

func NewSessionManager(secretKey []byte) *SessionManager {
	r, err := rigid.NewRigid(secretKey, 12)
	if err != nil {
		log.Fatal(err)
	}
	
	return &SessionManager{rigid: r}
}

func (s *SessionManager) CreateSession(userID, ipAddress string) string {
	metadata := fmt.Sprintf("session:%s:ip:%s", userID, ipAddress)
	sessionID, err := s.rigid.Generate(metadata)
	if err != nil {
		log.Fatal(err)
	}
	return sessionID
}

func (s *SessionManager) ValidateSession(sessionID string) bool {
	result, err := s.rigid.Verify(sessionID)
	if err != nil {
		return false
	}
	return result.Valid
}

func main() {
	fmt.Println("=== Advanced Rigid ULID Usage ===\n")
	
	secretKey := []byte("application-secret-key-2024")
	
	fmt.Println("1. User Management System:")
	userService := NewUserService(secretKey)
	
	users := []struct {
		username string
		role     string
	}{
		{"alice", "admin"},
		{"bob", "user"},
		{"charlie", "moderator"},
	}
	
	userIDs := make([]string, len(users))
	for i, user := range users {
		userIDs[i] = userService.CreateUser(user.username, user.role)
		fmt.Printf("   Created user %s (%s): %s\n", user.username, user.role, userIDs[i])
		
		time.Sleep(1 * time.Millisecond)
	}
	
	fmt.Println("\n2. User Validation:")
	for i, userID := range userIDs {
		valid, metadata, createdAt, err := userService.ValidateUser(userID)
		if err != nil {
			fmt.Printf("   User %d: ERROR (%s)\n", i+1, err)
		} else if valid {
			fmt.Printf("   User %d: VALID - %s (created %s)\n", i+1, metadata, createdAt)
		} else {
			fmt.Printf("   User %d: INVALID\n", i+1)
		}
	}
	
	fmt.Println("\n3. Session Management:")
	sessionManager := NewSessionManager(secretKey)
	
	sessions := make([]string, len(userIDs))
	for i, userID := range userIDs {
		ipAddress := fmt.Sprintf("192.168.1.%d", i+10)
		sessions[i] = sessionManager.CreateSession(userID, ipAddress)
		fmt.Printf("   Session for user %d: %s\n", i+1, sessions[i])
	}
	
	fmt.Println("\n4. Session Validation:")
	for i, sessionID := range sessions {
		valid := sessionManager.ValidateSession(sessionID)
		fmt.Printf("   Session %d: %t\n", i+1, valid)
	}
	
	fmt.Println("\n5. Multi-instance compatibility:")
	
	userService2 := NewUserService(secretKey)
	
	fmt.Printf("   Can service2 validate user1? ")
	valid, _, _, err := userService2.ValidateUser(userIDs[0])
	if err != nil {
		fmt.Printf("ERROR (%s)\n", err)
	} else {
		fmt.Printf("%t\n", valid)
	}
	
	fmt.Println("\n6. Different signature lengths:")
	lengths := []int{4, 8, 16, 32}
	
	for _, length := range lengths {
		r, err := rigid.NewRigid(secretKey, length)
		if err != nil {
			log.Fatal(err)
		}
		
		rigidID, err := r.Generate("test")
		if err != nil {
			log.Fatal(err)
		}
		
		fmt.Printf("   Signature length %d: %s\n", length, rigidID)
	}
	
	fmt.Println("\n7. Tamper detection:")
	originalID := userIDs[0]
	
	parts := []string{}
	for _, part := range []string{"01", "02", "03"} {
		parts = append(parts, originalID[:26]+"-"+part+originalID[29:])
	}
	
	fmt.Printf("   Original ID: %s\n", originalID)
	for i, tamperedID := range parts {
		valid, _, _, err := userService.ValidateUser(tamperedID)
		if err != nil {
			fmt.Printf("   Tampered %d: DETECTED (%s)\n", i+1, err)
		} else {
			fmt.Printf("   Tampered %d: %t\n", i+1, valid)
		}
	}
}