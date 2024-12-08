package jwt_test

import (
	"time"

	jwtV5 "github.com/golang-jwt/jwt/v5"
	"github.com/metadiv-io/jwt"
	"github.com/metadiv-io/rsa"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encode", func() {
	var (
		claims *jwt.Claims
		now    time.Time
	)

	BeforeEach(func() {
		claims = jwt.NewClaims()
		now = time.Now().UTC().Truncate(time.Second)
	})

	Context("EncodeWithSecret", func() {
		It("should encode claims with secret successfully", func() {
			// Setup test claims
			claims.SetIssuer("test-issuer")
			claims.SetSubject("test-subject")
			claims.SetAudience("test-audience")
			claims.SetExpirationTime(now.Add(time.Hour))
			claims.SetIssuedAt(now)
			claims.SetNotBefore(now)
			claims.SetID("test-id")
			claims.SetValue("custom-claim", "custom-value")

			// Encode
			secret := "test-secret"
			token, err := jwt.EncodeWithSecret(claims, secret)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			// Verify the token can be decoded
			parsedToken, err := jwtV5.ParseWithClaims(token, jwtV5.MapClaims{}, func(token *jwtV5.Token) (interface{}, error) {
				return []byte(secret), nil
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedToken.Valid).To(BeTrue())

			// Verify claims
			parsedClaims := parsedToken.Claims.(jwtV5.MapClaims)
			Expect(parsedClaims["iss"]).To(Equal("test-issuer"))
			Expect(parsedClaims["sub"]).To(Equal("test-subject"))
			Expect(parsedClaims["aud"]).To(Equal("test-audience"))
			Expect(parsedClaims["jti"]).To(Equal("test-id"))
			Expect(parsedClaims["custom-claim"]).To(Equal("custom-value"))
		})

		It("should encode empty claims", func() {
			token, err := jwt.EncodeWithSecret(claims, "secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())
		})
	})

	Context("EncodeWithKey", func() {
		var privateKey *rsa.PrivateKey

		BeforeEach(func() {
			var err error
			privateKey, err = rsa.NewRSAKey(2048)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should encode claims with RSA key successfully", func() {
			// Setup test claims
			claims.SetIssuer("test-issuer")
			claims.SetSubject("test-subject")
			claims.SetAudience("test-audience")
			claims.SetExpirationTime(now.Add(time.Hour))
			claims.SetIssuedAt(now)
			claims.SetNotBefore(now)
			claims.SetID("test-id")
			claims.SetValue("custom-claim", "custom-value")

			// Encode
			token, err := jwt.EncodeWithKey(claims, privateKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			// Verify the token can be decoded
			publicKey, err := jwtV5.ParseRSAPublicKeyFromPEM([]byte(privateKey.PublicKey().Pem()))
			Expect(err).NotTo(HaveOccurred())

			parsedToken, err := jwtV5.ParseWithClaims(token, jwtV5.MapClaims{}, func(token *jwtV5.Token) (interface{}, error) {
				return publicKey, nil
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedToken.Valid).To(BeTrue())

			// Verify claims
			parsedClaims := parsedToken.Claims.(jwtV5.MapClaims)
			Expect(parsedClaims["iss"]).To(Equal("test-issuer"))
			Expect(parsedClaims["sub"]).To(Equal("test-subject"))
			Expect(parsedClaims["aud"]).To(Equal("test-audience"))
			Expect(parsedClaims["jti"]).To(Equal("test-id"))
			Expect(parsedClaims["custom-claim"]).To(Equal("custom-value"))
		})

		It("should encode empty claims with RSA key", func() {
			token, err := jwt.EncodeWithKey(claims, privateKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())
		})

		It("should fail with invalid private key", func() {
			_, err := jwt.EncodeWithKey(claims, nil)
			Expect(err).To(HaveOccurred())
		})
	})
})
