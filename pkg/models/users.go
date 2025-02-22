// Package models defines data structures and validation logic.
package models

import (
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"` // "-" means this field won't be included in JSON
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserRegistration struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *UserRegistration) Validate() error {
	// Username validation
	if len(r.Username) < 3 || len(r.Username) > 32 {
		return fmt.Errorf("username must be between 3 and 32 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(r.Username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens")
	}

	// Email validation
	if !regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(r.Email) {
		return fmt.Errorf("invalid email format")
	}

	// Password validation
	if len(r.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(r.Password) > 72 {
		return fmt.Errorf("password is too long")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(r.Password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(r.Password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(r.Password) {
		return fmt.Errorf("password must contain at least one number")
	}
	if !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(r.Password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

func (u *User) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

// Sanitize removes sensitive data before sending to client
func (u *User) Sanitize() {
	u.Password = ""
}
