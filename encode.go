package jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metadiv-io/rsa"
)

// EncodeWithSecret encodes the claims with a secret
// It returns the signed token as a string, or an error if the encoding fails.
func EncodeWithSecret(claims *Claims, secret string) (string, error) {
	jwtClaims := jwt.MapClaims{}
	for key, value := range claims.values {
		jwtClaims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	return token.SignedString([]byte(secret))
}

// EncodeWithKey encodes the claims with a private key
// It returns the signed token as a string, or an error if the encoding fails.
func EncodeWithKey(claims *Claims, key *rsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("jwt error - private key is nil")
	}
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key.Pem()))
	if err != nil {
		return "", fmt.Errorf("jwt error - parsing private pem: %w", err)
	}
	jwtClaims := jwt.MapClaims{}
	for key, value := range claims.values {
		jwtClaims[key] = value
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims).SignedString(parsedKey)
}
