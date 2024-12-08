package jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metadiv-io/rsa"
)

// DecodeUnverified decodes the token without verifying it
// It returns the claims, or an error if the decoding fails.
func DecodeUnverified(token string) (*Claims, error) {
	jwtToken, err := jwt.Parse(token, nil)
	if err != nil && err.Error() != "token is unverifiable: no keyfunc was provided" {
		return nil, err
	}
	return jwtTokenToClaims(jwtToken)
}

// DecodeWithSecret decodes the token with a secret
// It returns the claims, or an error if the decoding fails.
func DecodeWithSecret(token, secret string) (*Claims, error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return jwtTokenToClaims(jwtToken)
}

// DecodeWithKey decodes the token with a public key
// It returns the claims, or an error if the decoding fails.
func DecodeWithKey(token string, key *rsa.PublicKey) (*Claims, error) {
	if key == nil {
		return nil, fmt.Errorf("jwt error - public key is nil")
	}
	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key.Pem()))
	if err != nil {
		return nil, err
	}
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return parsedKey, nil
	})
	if err != nil {
		return nil, err
	}
	return jwtTokenToClaims(jwtToken)
}

func jwtTokenToClaims(token *jwt.Token) (*Claims, error) {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("jwt: invalid claims")
	}
	jwt := NewClaims()
	for key, value := range mapClaims {
		jwt.SetValue(key, value)
	}
	return jwt, nil
}
