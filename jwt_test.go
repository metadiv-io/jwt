package jwt_test

import (
	"time"

	"github.com/metadiv-io/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("test: sign/parse token", func() {

	var secret = "6w9z$C&F)J@NcRfUjWnZr4u7x!A%D*G-"

	var createModClaim = func() *jwt.Claims {
		claims := jwt.NewClaims()
		claims.Set("foo", "bar")
		claims.Set("foo2", 123)
		return claims
	}

	It("should be able to sign and parse token", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		claims, err = jwt.FromToken(token, secret)
		Expect(err).To(BeNil())
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(float64(123)))
	})

	It("should be able to parse token without secret", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		claims, err = jwt.FromTokenUnverified(token)
		Expect(err).To(BeNil())
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(float64(123)))
	})

	It("should not be able to parse invalid token", func() {
		claims, err := jwt.FromToken("invalid token", secret)
		Expect(err).ToNot(BeNil())
		Expect(claims).To(BeNil())

		claims, err = jwt.FromTokenUnverified("invalid token")
		Expect(err).ToNot(BeNil())
		Expect(claims).To(BeNil())
	})

	It("should not be able to parse token with wrong secret", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		claims, err = jwt.FromToken(token, secret+"1")
		Expect(err).ToNot(BeNil())
		Expect(claims).To(BeNil())
	})

	It("should not able to parse expired token", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, -time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		claims, err = jwt.FromToken(token, secret)
		Expect(err).ToNot(BeNil())
		Expect(claims).To(BeNil())
	})

	It("should able to refresh token", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		token, err = jwt.RefreshToken(token, secret, time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		claims, err = jwt.FromToken(token, secret)
		Expect(err).To(BeNil())
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(float64(123)))
	})

	It("should not able to refresh token with wrong secret", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		token, err = jwt.RefreshToken(token, secret+"1", time.Hour)
		Expect(err).ToNot(BeNil())
		Expect(token).To(BeEmpty())
	})

	It("should not able to refresh expired token", func() {
		claims := createModClaim()
		Expect(claims.Get("foo")).To(Equal("bar"))
		Expect(claims.Get("foo2")).To(Equal(123))

		token, err := jwt.ToToken(claims, secret, -time.Hour)
		Expect(err).To(BeNil())
		Expect(len(token)).To(BeNumerically(">", 0))

		token, err = jwt.RefreshToken(token, secret, time.Hour)
		Expect(err).ToNot(BeNil())
		Expect(token).To(BeEmpty())
	})
})
