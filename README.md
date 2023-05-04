# jwt

## Installation

```bash
go get -u github.com/metadiv-io/jwt
```

## Highlights

### Claims

* jwt.NewClaims() *Claims

* claims.Set(key string, value interface{})

* claims.Get(key string) interface{}

### Jwt

* ToToken(claims *Claims, secret string, expiredAfter time.Duration) (string, error)

* RefreshToken(token, secret string, expiredAfter time.Duration) (string, error)

* FromToken(token, secret string) (*Claims, error)

* FromTokenUnverified(token string) (*Claims, error)