package jwt_test

import (
	"time"

	"github.com/metadiv-io/jwt"
	"github.com/metadiv-io/rsa"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Decode", func() {
	var (
		claims    *jwt.Claims
		now       time.Time
		token     string
		secret    string
		rsaKey    *rsa.PrivateKey
		publicKey *rsa.PublicKey
	)

	BeforeEach(func() {
		var err error
		claims = jwt.NewClaims()
		now = time.Now().UTC().Truncate(time.Second)
		secret = "test-secret"

		// Setup RSA keys
		rsaKey, err = rsa.NewRSAKey(2048)
		Expect(err).NotTo(HaveOccurred())
		publicKey = rsaKey.PublicKey()

		// Setup test claims
		claims.SetIssuer("test-issuer")
		claims.SetSubject("test-subject")
		claims.SetAudience("test-audience")
		claims.SetExpirationTime(now.Add(time.Hour))
		claims.SetIssuedAt(now)
		claims.SetNotBefore(now)
		claims.SetID("test-id")
		claims.SetValue("custom-claim", "custom-value")
	})

	Context("DecodeUnverified", func() {
		It("should decode an HMAC token without verification", func() {
			var err error
			token, err = jwt.EncodeWithSecret(claims, secret)
			Expect(err).NotTo(HaveOccurred())

			decodedClaims, err := jwt.DecodeUnverified(token)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedClaims.GetIssuer()).To(Equal("test-issuer"))
			Expect(decodedClaims.GetSubject()).To(Equal("test-subject"))
			Expect(decodedClaims.GetAudience()).To(Equal("test-audience"))
			Expect(decodedClaims.GetID()).To(Equal("test-id"))
			Expect(decodedClaims.GetValue("custom-claim")).To(Equal("custom-value"))
		})

		It("should decode an RSA token without verification", func() {
			var err error
			token, err = jwt.EncodeWithKey(claims, rsaKey)
			Expect(err).NotTo(HaveOccurred())

			decodedClaims, err := jwt.DecodeUnverified(token)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedClaims.GetIssuer()).To(Equal("test-issuer"))
			Expect(decodedClaims.GetValue("custom-claim")).To(Equal("custom-value"))
		})

		It("should fail with invalid token format", func() {
			_, err := jwt.DecodeUnverified("invalid.token.format")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("DecodeWithSecret", func() {
		BeforeEach(func() {
			var err error
			token, err = jwt.EncodeWithSecret(claims, secret)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should decode a valid token", func() {
			decodedClaims, err := jwt.DecodeWithSecret(token, secret)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedClaims.GetIssuer()).To(Equal("test-issuer"))
			Expect(decodedClaims.GetSubject()).To(Equal("test-subject"))
			Expect(decodedClaims.GetAudience()).To(Equal("test-audience"))
			Expect(decodedClaims.GetID()).To(Equal("test-id"))
			Expect(decodedClaims.GetValue("custom-claim")).To(Equal("custom-value"))
		})

		It("should fail with wrong secret", func() {
			_, err := jwt.DecodeWithSecret(token, "wrong-secret")
			Expect(err).To(HaveOccurred())
		})

		It("should fail with invalid token format", func() {
			_, err := jwt.DecodeWithSecret("invalid.token.format", secret)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("DecodeWithKey", func() {
		BeforeEach(func() {
			var err error
			token, err = jwt.EncodeWithKey(claims, rsaKey)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should decode a valid token", func() {
			decodedClaims, err := jwt.DecodeWithKey(token, publicKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedClaims.GetIssuer()).To(Equal("test-issuer"))
			Expect(decodedClaims.GetSubject()).To(Equal("test-subject"))
			Expect(decodedClaims.GetAudience()).To(Equal("test-audience"))
			Expect(decodedClaims.GetID()).To(Equal("test-id"))
			Expect(decodedClaims.GetValue("custom-claim")).To(Equal("custom-value"))
		})

		It("should fail with wrong public key", func() {
			wrongKey, err := rsa.NewRSAKey(2048)
			Expect(err).NotTo(HaveOccurred())
			_, err = jwt.DecodeWithKey(token, wrongKey.PublicKey())
			Expect(err).To(HaveOccurred())
		})

		It("should fail with invalid token format", func() {
			_, err := jwt.DecodeWithKey("invalid.token.format", publicKey)
			Expect(err).To(HaveOccurred())
		})

		It("should fail with invalid public key PEM", func() {
			_, err := jwt.DecodeWithKey(token, nil)
			Expect(err).To(HaveOccurred())
		})
	})
})
