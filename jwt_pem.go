package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

/*
Generate a token from the claims using the private pem.
*/
func (c *Claims) ToTokenByPrivatePEM(privPEM string, expiredAfter time.Duration) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privPEM))
	if err != nil {
		return "", fmt.Errorf("jwt error - parsing private pem: %w", err)
	}
	jwtClaims := jwt.MapClaims{}
	jwtClaims["exp"] = time.Now().Add(expiredAfter).Unix()
	for key, value := range c.data {
		jwtClaims[key] = value
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims).SignedString(key)
}

/*
Parse a token using the public pem and return the claims.
*/
func ParseTokenByPublicPEM(token, pubPEM string) *Claims {
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		return nil
	}
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil
	}
	return jwtTokenToClaims(jwtToken)
}
