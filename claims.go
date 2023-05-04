package jwt

// Claims is a simple claims implementation
// that can be used to store and retrieve
// claims data.
type Claims struct {
	data map[string]interface{}
}

// NewClaims creates a new Claims instance.
func NewClaims() *Claims {
	return &Claims{
		data: make(map[string]interface{}),
	}
}

// Set sets a claim value.
func (c *Claims) Set(key string, value interface{}) {
	c.data[key] = value
}

// Get gets a claim value.
func (c *Claims) Get(key string) interface{} {
	return c.data[key]
}
