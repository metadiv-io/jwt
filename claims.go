package jwt

import (
	"time"
)

// NewClaims creates a new Claims instance
func NewClaims() *Claims {
	return &Claims{
		values: make(map[string]any),
	}
}

// Claims represents the claims in a JWT
type Claims struct {
	values map[string]any
}

// SetIssuer sets the issuer of the token
// issuer is about who issued the token
// issuer is the standard claim key: "iss"
func (c *Claims) SetIssuer(issuer string) {
	c.values[KeyIssuer] = issuer
}

// GetIssuer gets the issuer of the token
// issuer is about who issued the token
// issuer is the standard claim key: "iss"
func (c *Claims) GetIssuer() string {
	return c.getString(KeyIssuer)
}

// SetSubject sets the subject of the token
// subject is about who or what the token is intended for
// subject is the standard claim key: "sub"
func (c *Claims) SetSubject(subject string) {
	c.values[KeySubject] = subject
}

// GetSubject gets the subject of the token
// subject is about who or what the token is intended for
// subject is the standard claim key: "sub"
func (c *Claims) GetSubject() string {
	return c.getString(KeySubject)
}

// SetAudience sets the audience of the token
// audience is about who or what the token is intended for
// audience is the standard claim key: "aud"
func (c *Claims) SetAudience(audience string) {
	c.values[KeyAudience] = audience
}

// GetAudience gets the audience of the token
// audience is about who or what the token is intended for
// audience is the standard claim key: "aud"
func (c *Claims) GetAudience() string {
	return c.getString(KeyAudience)
}

// SetExpirationTime sets the expiration time of the token, as unix time
// expiration time is the standard claim key: "exp"
func (c *Claims) SetExpirationTime(expirationTime time.Time) {
	c.values[KeyExpirationTime] = float64(expirationTime.Unix())
}

// GetExpirationTime gets the expiration time of the token, as unix time
// expiration time is the standard claim key: "exp"
func (c *Claims) GetExpirationTime() time.Time {
	return time.Unix(c.getInteger(KeyExpirationTime), 0)
}

// SetNotBefore sets the not before time of the token, as unix time
// not before is about when the token is not valid yet
// not before is the standard claim key: "nbf"
func (c *Claims) SetNotBefore(notBefore time.Time) {
	c.values[KeyNotBefore] = float64(notBefore.Unix())
}

// GetNotBefore gets the not before time of the token, as unix time
// not before is about when the token is not valid yet
// not before is the standard claim key: "nbf"
func (c *Claims) GetNotBefore() time.Time {
	return time.Unix(c.getInteger(KeyNotBefore), 0)
}

// SetIssuedAt sets the issued at time of the token, as unix time
// issued at is the standard claim key: "iat"
func (c *Claims) SetIssuedAt(issuedAt time.Time) {
	c.values[KeyIssuedAt] = float64(issuedAt.Unix())
}

// GetIssuedAt gets the issued at time of the token, as unix time
// issued at is the standard claim key: "iat"
func (c *Claims) GetIssuedAt() time.Time {
	return time.Unix(c.getInteger(KeyIssuedAt), 0)
}

// SetID sets the ID of the token
// ID is the standard claim key: "jti"
func (c *Claims) SetID(id string) {
	c.values[KeyID] = id
}

// GetID gets the ID of the token
// ID is the standard claim key: "jti"
func (c *Claims) GetID() string {
	return c.getString(KeyID)
}

// GetValue gets the value of the claim
func (c *Claims) GetValue(key string) any {
	return c.values[key]
}

// SetValue sets the value of the claim
func (c *Claims) SetValue(key string, value any) {
	c.values[key] = value
}

func (c *Claims) getString(key string) string {
	v, ok := c.values[key]
	if !ok {
		return ""
	}
	return v.(string)
}

func (c *Claims) getInteger(key string) int64 {
	v, ok := c.values[key]
	if !ok {
		return 0
	}
	return int64(v.(float64))
}
