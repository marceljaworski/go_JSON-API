package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("secret-key")

type Auth interface {
	CreateToken(string) (string, error)
	VerifyToken(string) error
}

const jwtSecret = "notsecret" // Do not do that in Produccion. Better, in the terminal write: export JWT_SECRET=supersecret

func CreateToken(firstName string) (string, error) {
	// jwtSecret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"firstName": firstName,
			"exp":       time.Now().Add(time.Hour * 24).Unix(),
		})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}
