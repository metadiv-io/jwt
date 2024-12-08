package jwt

// Standard claims keys
const (
	KeyIssuer         = "iss" // who issued the token
	KeySubject        = "sub" // subject of the token
	KeyAudience       = "aud" // who or what the token is intended for
	KeyExpirationTime = "exp" // expiration time, as unix time
	KeyNotBefore      = "nbf" // not before, as unix time
	KeyIssuedAt       = "iat" // issued at, as unix time
	KeyID             = "jti" // unique identifier for the token
)
