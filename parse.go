package jwt

import (
	"log"

	"github.com/golang-jwt/jwt"
)

/*
Parse a token without secret or pem.
*/
func UnverifiedParse(token string) *Jwt {
	jwtToken, err := jwt.Parse(token, nil)
	if err != nil && err.Error() != "no Keyfunc was provided." {
		log.Println(err)
		return nil
	}
	return jwtTokenToClaims(jwtToken)
}

/*
Parse a jwt token.
*/
func Parse(token string, secret string) *Jwt {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		log.Println("jwt:", err)
		return nil
	}
	return jwtTokenToClaims(jwtToken)
}

/*
Parse a jwt token by RSA public key.
*/
func ParseByRSA(token string, publicKey string) *Jwt {
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
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

func jwtTokenToClaims(token *jwt.Token) *Jwt {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("jwt: invalid claims")
		return nil
	}
	jwt := New()
	for key, value := range mapClaims {
		jwt.Set(key, value)
	}
	return jwt
}
