package jwt_test

import (
	"time"

	"github.com/metadiv-io/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Claims", func() {
	var claims *jwt.Claims

	BeforeEach(func() {
		claims = jwt.NewClaims()
	})

	Context("standard claims", func() {
		It("should handle issuer claim", func() {
			Expect(claims.GetIssuer()).To(BeEmpty())

			claims.SetIssuer("test-issuer")
			Expect(claims.GetIssuer()).To(Equal("test-issuer"))
		})

		It("should handle subject claim", func() {
			Expect(claims.GetSubject()).To(BeEmpty())

			claims.SetSubject("test-subject")
			Expect(claims.GetSubject()).To(Equal("test-subject"))
		})

		It("should handle audience claim", func() {
			Expect(claims.GetAudience()).To(BeEmpty())

			claims.SetAudience("test-audience")
			Expect(claims.GetAudience()).To(Equal("test-audience"))
		})

		It("should handle ID claim", func() {
			Expect(claims.GetID()).To(BeEmpty())

			claims.SetID("test-id")
			Expect(claims.GetID()).To(Equal("test-id"))
		})

		It("should handle expiration time claim", func() {
			defaultTime := time.Unix(0, 0)
			Expect(claims.GetExpirationTime()).To(Equal(defaultTime))

			now := time.Now().UTC().Truncate(time.Second)
			claims.SetExpirationTime(now)
			gotTime := claims.GetExpirationTime().UTC()
			Expect(gotTime).To(Equal(now))
		})

		It("should handle not before claim", func() {
			defaultTime := time.Unix(0, 0)
			Expect(claims.GetNotBefore()).To(Equal(defaultTime))

			now := time.Now().UTC().Truncate(time.Second)
			claims.SetNotBefore(now)
			gotTime := claims.GetNotBefore().UTC()
			Expect(gotTime).To(Equal(now))
		})

		It("should handle issued at claim", func() {
			defaultTime := time.Unix(0, 0)
			Expect(claims.GetIssuedAt()).To(Equal(defaultTime))

			now := time.Now().UTC().Truncate(time.Second)
			claims.SetIssuedAt(now)
			gotTime := claims.GetIssuedAt().UTC()
			Expect(gotTime).To(Equal(now))
		})
	})

	Context("custom claims", func() {
		It("should handle string values", func() {
			claims.SetValue("custom-key", "custom-value")
			Expect(claims.GetValue("custom-key")).To(Equal("custom-value"))
		})

		It("should handle numeric values", func() {
			claims.SetValue("custom-number", 42.5)
			Expect(claims.GetValue("custom-number")).To(Equal(42.5))
		})

		It("should handle boolean values", func() {
			claims.SetValue("custom-bool", true)
			Expect(claims.GetValue("custom-bool")).To(Equal(true))
		})

		It("should handle nil values", func() {
			claims.SetValue("custom-nil", nil)
			Expect(claims.GetValue("custom-nil")).To(BeNil())
		})

		It("should return nil for non-existent keys", func() {
			Expect(claims.GetValue("non-existent")).To(BeNil())
		})
	})

	Context("initialization", func() {
		It("should create new claims with empty values", func() {
			newClaims := jwt.NewClaims()
			Expect(newClaims).NotTo(BeNil())
			Expect(newClaims.GetIssuer()).To(BeEmpty())
			Expect(newClaims.GetSubject()).To(BeEmpty())
			Expect(newClaims.GetAudience()).To(BeEmpty())
			Expect(newClaims.GetID()).To(BeEmpty())
			Expect(newClaims.GetExpirationTime()).To(Equal(time.Unix(0, 0)))
			Expect(newClaims.GetNotBefore()).To(Equal(time.Unix(0, 0)))
			Expect(newClaims.GetIssuedAt()).To(Equal(time.Unix(0, 0)))
		})
	})
})
