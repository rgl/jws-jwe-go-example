package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// sign and encrypt a payload from alice to bob using jws and jwe.
func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	slog.SetDefault(logger)

	ctx := context.Background()

	signatureAlgorithm := jwa.RS256            // RSASSA-PKCS-v1.5 using SHA-256.
	keyEncryptionAlgorithm := jwa.RSA_OAEP_256 // RSA-OAEP-SHA256.
	contentEncryptionAlgorithm := jwa.A128GCM  // AES-GCM (128).

	alicePrivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate the alice private key", "error", err)
		return
	}
	alicePublicKey := alicePrivatekey.PublicKey

	bobPrivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate the bob private key", "error", err)
		return
	}
	bobPublicKey := bobPrivatekey.PublicKey

	payload := []byte(`Alice: Hello, Bob!`)

	slog.Info("payload", "length", len(payload), "payload", payload)

	iat := time.Now().UTC().Unix()
	exp := iat + int64(1*time.Hour/time.Second)

	// sign the headers and payload using JWS and JWS Compact Serialization.
	jwk, err := jwk.FromRaw(alicePublicKey)
	if err != nil {
		slog.Error("failed to convert public key to a jwk", "error", err)
		return
	}
	jwsHeaders := jws.NewHeaders()
	jwsHeaders.Set("typ", "jose")                         // type of token.
	jwsHeaders.Set("cty", "text/plain")                   // payload content type.
	jwsHeaders.Set("iat", iat)                            // issued at time.
	jwsHeaders.Set("nbf", iat)                            // not valid before time.
	jwsHeaders.Set("exp", exp)                            // expiration time.
	jwsHeaders.Set("jwk", jwk)                            // issuer public json web key. alternatively, use the kid parameter, or do not include this jwk parameter.
	jwsHeaders.Set("iss", "alice")                        // issuer.
	jwsHeaders.Set("aud", []string{"bob"})                // audience.
	jwsHeaders.Set("example.com", map[string]interface{}{ // custom properties.
		"jws-custom-property-key": "jws-custom-property-value",
	})
	jwsBytes, err := jws.Sign(
		payload,
		jws.WithKey(signatureAlgorithm, alicePrivatekey, jws.WithProtectedHeaders(jwsHeaders)),
	)
	if err != nil {
		slog.Error("failed to sign", "error", err)
		return
	}
	jwsHeadersMap, err := jwsHeaders.AsMap(ctx)
	if err != nil {
		slog.Error("failed to get the jws headers map", "error", err)
		return
	}
	slog.Info("signed", "length", len(jwsBytes), "jwsHeadersMap", jwsHeadersMap, "jwsBytes", jwsBytes)

	// encrypt and authenticate the payload using JWE and JWE Compact Serialization.
	// NB the headers are not encrypted. only the payload is.
	// NB the headers are protected from changes and are verified while the
	//    entire jwe is successfully decrypted.
	jweHeaders := jwe.NewHeaders()
	jweHeaders.Set("typ", "jose")                         // type of token.
	jweHeaders.Set("cty", "jose")                         // payload content type.
	jweHeaders.Set("iat", iat)                            // issued at time.
	jweHeaders.Set("nbf", iat)                            // not valid before time.
	jweHeaders.Set("exp", exp)                            // expiration time.
	jweHeaders.Set("iss", "alice")                        // issuer.
	jweHeaders.Set("aud", []string{"bob"})                // audience.
	jweHeaders.Set("example.com", map[string]interface{}{ // custom properties.
		"jwe-custom-property-key": "jwe-custom-property-value",
	})
	jweBytes, err := jwe.Encrypt(
		jwsBytes,
		jwe.WithProtectedHeaders(jweHeaders),
		jwe.WithKey(keyEncryptionAlgorithm, bobPublicKey),
		jwe.WithContentEncryption(contentEncryptionAlgorithm),
	)
	if err != nil {
		slog.Error("failed to encrypt", "error", err)
		return
	}
	jweHeadersMap, err := jweHeaders.AsMap(ctx)
	if err != nil {
		slog.Error("failed to get the encrypt headers map", "error", err)
		return
	}
	slog.Info("encrypted", "length", len(jweBytes), "jweHeadersMap", jweHeadersMap, "jweBytes", jweBytes)

	// decrypt.
	var decryptedMessage jwe.Message
	decryptedPayload, err := jwe.Decrypt(
		jweBytes,
		jwe.WithKey(keyEncryptionAlgorithm, bobPrivatekey),
		jwe.WithMessage(&decryptedMessage),
	)
	if err != nil {
		slog.Error("failed to decrypt", "error", err)
		return
	}
	decryptedHeadersMap, err := decryptedMessage.ProtectedHeaders().AsMap(ctx)
	if err != nil {
		slog.Error("failed to get the decrypted headers", "error", err)
		return
	}
	slog.Info("decrypted", "length", len(decryptedPayload), "decryptedHeadersMap", decryptedHeadersMap, "decryptedPayload", decryptedPayload)

	// verify (integrity and signature).
	var verifiedMessage jws.Message
	verifiedPayload, err := jws.Verify(
		decryptedPayload,
		jws.WithKey(signatureAlgorithm, alicePublicKey),
		jws.WithMessage(&verifiedMessage),
	)
	if err != nil {
		slog.Error("failed to verify", "error", err)
		return
	}
	verifiedMessageSignatures := verifiedMessage.Signatures()
	if len(verifiedMessageSignatures) != 1 {
		slog.Error("failed to verify because it does not only have one signature")
		return
	}
	verifiedHeadersMap, err := verifiedMessageSignatures[0].ProtectedHeaders().AsMap(ctx)
	if err != nil {
		slog.Error("failed to get the decrypted headers", "error", err)
		return
	}

	slog.Info("partial verified", "length", len(verifiedPayload), "verifiedHeadersMap", verifiedHeadersMap, "verifiedPayload", verifiedPayload)

	// verify the issuer.
	issuer, ok := verifiedHeadersMap["iss"].(string)
	if !ok || issuer != "alice" {
		slog.Error("failed to validate the issuer")
		return
	}

	// verify the audience.
	audience, ok := verifiedHeadersMap["aud"].([]interface{})
	if !ok || len(audience) != 1 || audience[0] != "bob" {
		slog.Error("failed to validate the audience")
		return
	}

	// verify the times.
	// TODO clock skew?
	currentTime := float64(time.Now().UTC().Unix())
	issuedAtTime, ok := verifiedHeadersMap["iat"].(float64)
	if !ok || currentTime > issuedAtTime {
		slog.Error("failed to validate issued at time")
		return
	}
	notValidBeforeTime, ok := verifiedHeadersMap["nbf"].(float64)
	if !ok || currentTime > notValidBeforeTime {
		slog.Error("failed to validate not valid before time")
		return
	}
	expirationTime, ok := verifiedHeadersMap["exp"].(float64)
	if !ok || currentTime > expirationTime {
		slog.Error("failed to validate expiration time")
		return
	}

	slog.Info("verified", "length", len(verifiedPayload), "verifiedHeadersMap", verifiedHeadersMap, "verifiedPayload", verifiedPayload)
}
