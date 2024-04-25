package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type Jwt struct {
	data map[string]any
}

/*
New jwt instance.
*/
func New() *Jwt {
	return &Jwt{
		data: make(map[string]any),
	}
}

/*
Set a claim.
*/
func (j *Jwt) Set(key string, value any) {
	j.data[key] = value
}

/*
Get a claim.
*/
func (j *Jwt) Get(key string) any {
	return j.data[key]
}

/*
Encode by secret.
*/
func (j *Jwt) Encode(secret string, expiredAfter time.Duration) (string, error) {
	jwtClaims := jwt.MapClaims{}
	jwtClaims["exp"] = time.Now().Add(expiredAfter).Unix()
	for key, value := range j.data {
		jwtClaims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	return token.SignedString([]byte(secret))
}

/*
Encode by RSA private key.
*/
func (j *Jwt) EncodeByRSA(privateKey string, expiredAfter time.Duration) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		return "", fmt.Errorf("jwt error - parsing private pem: %w", err)
	}
	jwtClaims := jwt.MapClaims{}
	jwtClaims["exp"] = time.Now().Add(expiredAfter).Unix()
	for key, value := range j.data {
		jwtClaims[key] = value
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims).SignedString(key)
}
