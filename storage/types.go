package storage

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Email    string `json: "email"`
	Password string `json: "password"`
}

type LoginResponse struct {
	ID    int    `json: "id"`
	Token string `json: "token"`
}

type TransferRequest struct {
	ToAccount int `json: "toAccount"`
	Amount    int `json: "amount"`
}

type CreateAccountRequest struct {
	FirstName string `json: "firstName"`
	LastName  string `json: "lastName"`
	Password  string `json: "password"`
}

type Account struct {
	ID        int       `json: "id"`
	FirstName string    `json: "firstName"`
	LastName  string    `json: "lastName"`
	Email     string    `json: "email"`
	Password  string    `json: "password"`
	Number    int64     `json: "number"`
	Balance   int64     `json: "balance"`
	CreatedAt time.Time `json: "createdAt`
}

func NewAccount(firstName, lastName string, password string) (*Account, error) {
	encryptpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Account{
		// ID:        rand.Intn(10000),
		FirstName: firstName,
		LastName:  lastName,
		// Email: email,
		Password: string(encryptpass),
		Number:   int64(rand.Intn(1000000)),
		// Balance: balance,
		CreatedAt: time.Now().UTC(),
	}, nil
}
