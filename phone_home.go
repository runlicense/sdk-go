package runlicense

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// phoneHomeTimeout is the default HTTP request timeout for phone-home validation.
const phoneHomeTimeout = 30 * time.Second

// maxResponseSize is the maximum size of a phone-home response body (1 MB).
const maxResponseSize = 1 << 20

// phoneHome performs phone-home validation against the activation server.
// Returns the validated token and the raw signed token string for caching.
func phoneHome(ctx context.Context, payload *LicensePayload, publicKeyB64 string) (*ValidationToken, string, error) {
	if payload.ActivationURL == nil {
		return nil, "", &LicenseError{Code: ErrNoActivationURL}
	}
	activationURL := *payload.ActivationURL

	nonce, err := generateNonce()
	if err != nil {
		return nil, "", &LicenseError{Code: ErrPhoneHomeFailed, Message: err.Error()}
	}

	nonceSig, err := signNonce(nonce, publicKeyB64)
	if err != nil {
		return nil, "", err
	}

	body, _ := json.Marshal(map[string]string{
		"nonce":           nonce,
		"nonce_signature": nonceSig,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, activationURL, bytes.NewReader(body))
	if err != nil {
		return nil, "", &LicenseError{Code: ErrPhoneHomeFailed, Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: phoneHomeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", &LicenseError{Code: ErrPhoneHomeFailed, Message: err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, "", &LicenseError{Code: ErrPhoneHomeFailed, Message: err.Error()}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", &LicenseError{
			Code:    ErrServerRejected,
			Message: fmt.Sprintf("HTTP %d — %s", resp.StatusCode, string(respBody)),
		}
	}

	var respJSON struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &respJSON); err != nil {
		return nil, "", &LicenseError{Code: ErrPhoneHomeFailed, Message: err.Error()}
	}

	if respJSON.Token == "" {
		return nil, "", &LicenseError{Code: ErrInvalidValidationToken}
	}

	token, err := verifyToken(respJSON.Token, publicKeyB64, nonce, payload.LicenseID)
	if err != nil {
		return nil, "", err
	}

	return token, respJSON.Token, nil
}

// verifyToken verifies a signed validation token from the server.
func verifyToken(tokenStr, publicKeyB64, expectedNonce, expectedLicenseID string) (*ValidationToken, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}

	tokenPayloadBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}

	tokenSigBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}

	// Verify signature
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}
	pubKey := ed25519.PublicKey(keyBytes)

	if len(tokenSigBytes) != ed25519.SignatureSize {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}

	if !ed25519.Verify(pubKey, tokenPayloadBytes, tokenSigBytes) {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}

	// Parse token payload
	var token ValidationToken
	if err := json.Unmarshal(tokenPayloadBytes, &token); err != nil {
		return nil, &LicenseError{Code: ErrInvalidValidationToken}
	}

	// Validate nonce
	if token.Nonce != expectedNonce {
		return nil, &LicenseError{Code: ErrValidationTokenNonceMismatch}
	}

	// Validate license ID
	if token.LicenseID != expectedLicenseID {
		return nil, &LicenseError{Code: ErrValidationTokenLicenseMismatch}
	}

	// Validate expiry
	expiresAt, err := parseExpiryDate(token.ExpiresAt)
	if err != nil {
		return nil, &LicenseError{Code: ErrValidationTokenExpired}
	}
	if time.Now().UTC().After(expiresAt.UTC()) {
		return nil, &LicenseError{Code: ErrValidationTokenExpired}
	}

	return &token, nil
}

// signNonce signs a nonce with HMAC-SHA256 using the public key as the secret.
func signNonce(nonce, publicKeyB64 string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return "", &LicenseError{Code: ErrInvalidPublicKey}
	}

	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// generateNonce generates a 16-byte hex-encoded random nonce.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// cacheToken atomically stores the raw signed token string to disk.
func cacheToken(cacheDir, rawToken string) {
	path := filepath.Join(cacheDir, ".runlicense_token")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(rawToken), 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// loadCachedToken loads and cryptographically verifies a cached token from disk.
func loadCachedToken(cacheDir, publicKeyB64, expectedLicenseID string) *ValidationToken {
	path := filepath.Join(cacheDir, ".runlicense_token")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	rawToken := strings.TrimSpace(string(data))
	parts := strings.SplitN(rawToken, ".", 2)
	if len(parts) != 2 {
		return nil
	}

	tokenPayloadBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	tokenSigBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	// Verify signature
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil
	}
	pubKey := ed25519.PublicKey(keyBytes)

	if len(tokenSigBytes) != ed25519.SignatureSize {
		return nil
	}

	if !ed25519.Verify(pubKey, tokenPayloadBytes, tokenSigBytes) {
		return nil
	}

	// Parse and validate
	var token ValidationToken
	if err := json.Unmarshal(tokenPayloadBytes, &token); err != nil {
		return nil
	}

	if token.LicenseID != expectedLicenseID {
		return nil
	}

	expiresAt, err := parseExpiryDate(token.ExpiresAt)
	if err != nil {
		return nil
	}
	if time.Now().UTC().After(expiresAt.UTC()) {
		return nil
	}

	return &token
}
