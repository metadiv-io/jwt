package jwt

import (
	"log"

	"github.com/golang-jwt/jwt"
)

/*
Parse a token without secret or pem, then return the claims.
*/
func ParseTokenUnverified(token string) *Claims {
	jwtToken, err := jwt.Parse(token, nil)
	if err != nil && err.Error() != "no Keyfunc was provided." {
		log.Println(err)
		return nil
	}
	return jwtTokenToClaims(jwtToken)
}

func jwtTokenToClaims(token *jwt.Token) *Claims {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("invalid claims")
		return nil
	}
	claims := NewClaims()
	for key, value := range mapClaims {
		claims.Set(key, value)
	}
	return claims
}
