package jwt

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

/*
Generate a token from the claims using the secret.
*/
func (c *Claims) ToTokenBySecret(secret string, expiredAfter time.Duration) (string, error) {
	jwtClaims := jwt.MapClaims{}
	jwtClaims["exp"] = time.Now().Add(expiredAfter).Unix()
	for key, value := range c.data {
		jwtClaims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	return token.SignedString([]byte(secret))
}

/*
Parse a token using the secret and return the claims.
*/
func ParseTokenBySecret(token, secret string) *Claims {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		log.Println(err)
		return nil
	}
	return jwtTokenToClaims(jwtToken)
}
