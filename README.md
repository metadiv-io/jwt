# Jwt Issuer

This package provides jwt issuing and verification in "secret" or "rsa" way.

## Installation

```bash
go get -u github.com/metadiv-io/jwt
```

## Create a new jwt claims

Create new jwt claims:

```go
j := jwt.New()
```

Set the claims:

```go
j.Set("sub", "1234567890")
j.Set("name", "John Doe")
j.Set("admin", true)
```

Get the claims:

```go
sub := j.Get("sub")
name := j.Get("name")
admin := j.Get("admin")
```

## Issue a jwt token

Issue a jwt token with a secret and set the expiration time to 2 hours:

```go
token, err := j.Encode("secret", time.Hour * 2)
```

Issue a jwt token with a rsa private key and set the expiration time to 2 hours:

```go
token, err := j.EncodeByRSA(privateKey, time.Hour * 2)
```

## Verify a jwt token

Verify a jwt token without a secret or a rsa public key:

```go
j := jwt.UnverifiedParse(token)
```

Verify a jwt token with a secret:

```go
j := jwt.Parse(token, "secret")
```

Verify a jwt token with a rsa public key:

```go
j := jwt.ParseByRSA(token, publicKey)
```

## RSA key generation utility

This package provides a utility to generate rsa private and public keys:

```go
keyPair, err := jwt.CreateRSAKeyPair()
log.Println(keyPair.Private)
log.Println(keyPair.Public)
```
