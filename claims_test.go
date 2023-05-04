package jwt_test

import (
	"github.com/metadiv-io/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("test: jwt claims", func() {
	It("should be able to set and get claims", func() {
		claims := jwt.NewClaims()

		claims.Set("foo", "bar")
		Expect(claims.Get("foo")).To(Equal("bar"))

		claims.Set("foo2", 123)
		Expect(claims.Get("foo2")).To(Equal(123))
	})
})
