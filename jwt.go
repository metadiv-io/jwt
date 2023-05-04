package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
)

// FromTokenUnverified parses a token without secret and returns the claims.
func FromTokenUnverified(token string) (*Claims, error) {
	jwtToken, err := jwt.Parse(token, nil)
	if err != nil && err.Error() != "no Keyfunc was provided." {
		return nil, err
	}
	return jwtTokenToClaims(jwtToken)
}

// FromToken parses a token and returns the claims.
func FromToken(token, secret string) (*Claims, error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return jwtTokenToClaims(jwtToken)
}

// ToToken creates a token from the claims.
func ToToken(claims *Claims, secret string, expiredAfter time.Duration) (string, error) {
	jwtClaims := jwt.MapClaims{}
	jwtClaims["exp"] = time.Now().Add(expiredAfter).Unix()
	for key, value := range claims.data {
		jwtClaims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	return token.SignedString([]byte(secret))
}

// RefreshToken refreshes a token.
func RefreshToken(token, secret string, expiredAfter time.Duration) (string, error) {
	claims, err := FromToken(token, secret)
	if err != nil {
		return "", err
	}
	return ToToken(claims, secret, expiredAfter)
}

func jwtTokenToClaims(token *jwt.Token) (*Claims, error) {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	claims := NewClaims()
	for key, value := range mapClaims {
		claims.Set(key, value)
	}
	return claims, nil
}
