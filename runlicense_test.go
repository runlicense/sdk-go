package runlicense

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── Test helpers ──────────────────────────────────────────────────

func genKeypair(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func makeLicense(t *testing.T, privKey ed25519.PrivateKey, payload string) string {
	t.Helper()
	sig := ed25519.Sign(privKey, []byte(payload))
	lf := licenseFile{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(lf)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func makePayloadJSON(status string, expiryDate, activationURL *string, features json.RawMessage) string {
	p := map[string]any{
		"license_id":       "lic_test_123",
		"product_id":       "prod_test",
		"customer_id":      "cust_test",
		"status":           status,
		"expiry_date":      expiryDate,
		"allowed_features": features,
		"usage_limit":      nil,
		"token_ttl":        uint64(3600),
		"activation_url":   activationURL,
	}
	data, _ := json.Marshal(p)
	return string(data)
}

func strPtr(s string) *string { return &s }

func makeActiveLicense(t *testing.T, privKey ed25519.PrivateKey) string {
	t.Helper()
	return makeLicense(t, privKey, makePayloadJSON("active", nil, nil, nil))
}

func makeActiveLicenseWithExpiry(t *testing.T, privKey ed25519.PrivateKey, expiry string) string {
	t.Helper()
	return makeLicense(t, privKey, makePayloadJSON("active", strPtr(expiry), nil, nil))
}

func makeActiveLicenseWithFeatures(t *testing.T, privKey ed25519.PrivateKey, features json.RawMessage) string {
	t.Helper()
	return makeLicense(t, privKey, makePayloadJSON("active", nil, nil, features))
}

func makeValidationToken(t *testing.T, privKey ed25519.PrivateKey, licenseID, nonce, expiresAt string) string {
	t.Helper()
	tokenPayload := map[string]string{
		"license_id": licenseID,
		"nonce":      nonce,
		"issued_at":  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"expires_at": expiresAt,
	}
	payloadBytes, _ := json.Marshal(tokenPayload)
	sig := ed25519.Sign(privKey, payloadBytes)
	return base64.StdEncoding.EncodeToString(payloadBytes) + "." + base64.StdEncoding.EncodeToString(sig)
}

func assertErrorCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var licErr *LicenseError
	if !errors.As(err, &licErr) {
		t.Fatalf("expected *LicenseError, got %T: %v", err, err)
	}
	if licErr.Code != code {
		t.Fatalf("expected error code %d, got %d: %s", code, licErr.Code, licErr.Error())
	}
}

// ── Signature verification tests ──────────────────────────────────

func TestValidSignatureRoundtrip(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)
	payload, err := verifySignature(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if payload.LicenseID != "lic_test_123" {
		t.Errorf("got license_id %q", payload.LicenseID)
	}
	if payload.ProductID != "prod_test" {
		t.Errorf("got product_id %q", payload.ProductID)
	}
	if payload.CustomerID != "cust_test" {
		t.Errorf("got customer_id %q", payload.CustomerID)
	}
	if payload.Status != "active" {
		t.Errorf("got status %q", payload.Status)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	sk, _ := genKeypair(t)
	_, pk2 := genKeypair(t)
	license := makeActiveLicense(t, sk)
	_, err := verifySignature(license, pk2)
	assertErrorCode(t, err, ErrSignatureMismatch)
}

func TestTamperedPayloadRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)

	var parsed map[string]any
	json.Unmarshal([]byte(license), &parsed)
	parsed["payload"] = `{"license_id":"lic_stolen","product_id":"prod_test","customer_id":"cust_test","status":"active","expiry_date":null,"allowed_features":null,"usage_limit":null,"token_ttl":3600,"activation_url":null}`
	tampered, _ := json.Marshal(parsed)

	_, err := verifySignature(string(tampered), pk)
	assertErrorCode(t, err, ErrSignatureMismatch)
}

func TestTamperedSignatureRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)

	var parsed map[string]any
	json.Unmarshal([]byte(license), &parsed)
	sig := parsed["signature"].(string)
	// Flip last character
	chars := []byte(sig)
	if chars[len(chars)-1] == 'A' {
		chars[len(chars)-1] = 'B'
	} else {
		chars[len(chars)-1] = 'A'
	}
	parsed["signature"] = string(chars)
	tampered, _ := json.Marshal(parsed)

	_, err := verifySignature(string(tampered), pk)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	_, pk := genKeypair(t)
	_, err := verifySignature("not json", pk)
	assertErrorCode(t, err, ErrInvalidJSON)
}

func TestMissingPayloadFieldRejected(t *testing.T) {
	_, pk := genKeypair(t)
	_, err := verifySignature(`{"signature": "abc"}`, pk)
	// Empty payload string will fail on signature decode
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMissingSignatureFieldRejected(t *testing.T) {
	_, pk := genKeypair(t)
	_, err := verifySignature(`{"payload": "abc"}`, pk)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestInvalidPublicKeyRejected(t *testing.T) {
	sk, _ := genKeypair(t)
	license := makeActiveLicense(t, sk)

	// Too short
	_, err := verifySignature(license, base64.StdEncoding.EncodeToString([]byte("tooshort")))
	assertErrorCode(t, err, ErrInvalidPublicKey)

	// Not valid base64
	_, err = verifySignature(license, "!!!not-base64!!!")
	assertErrorCode(t, err, ErrInvalidPublicKey)

	// Empty
	_, err = verifySignature(license, "")
	assertErrorCode(t, err, ErrInvalidPublicKey)
}

func TestInvalidSignatureEncodingRejected(t *testing.T) {
	_, pk := genKeypair(t)
	j, _ := json.Marshal(map[string]string{
		"payload":   makePayloadJSON("active", nil, nil, nil),
		"signature": "!!!not-base64!!!",
	})
	_, err := verifySignature(string(j), pk)
	assertErrorCode(t, err, ErrInvalidSignature)
}

func TestSignatureTooShortRejected(t *testing.T) {
	_, pk := genKeypair(t)
	j, _ := json.Marshal(map[string]string{
		"payload":   makePayloadJSON("active", nil, nil, nil),
		"signature": base64.StdEncoding.EncodeToString([]byte("tooshort")),
	})
	_, err := verifySignature(string(j), pk)
	assertErrorCode(t, err, ErrInvalidSignature)
}

func TestInvalidPayloadJSONInEnvelope(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeLicense(t, sk, "not a json payload")
	_, err := verifySignature(license, pk)
	assertErrorCode(t, err, ErrInvalidJSON)
}

func TestPublicKeyWithWhitespaceAccepted(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)
	pkWithWhitespace := fmt.Sprintf("  %s  \n", pk)
	_, err := verifySignature(license, pkWithWhitespace)
	if err != nil {
		t.Fatal(err)
	}
}

// ── Status and expiry tests ───────────────────────────────────────

func TestActiveStatusAccepted(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)
	_, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuspendedStatusRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeLicense(t, sk, makePayloadJSON("suspended", nil, nil, nil))
	_, err := ActivateFromJSONOffline(license, pk)
	assertErrorCode(t, err, ErrLicenseNotActive)
}

func TestRevokedStatusRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeLicense(t, sk, makePayloadJSON("revoked", nil, nil, nil))
	_, err := ActivateFromJSONOffline(license, pk)
	assertErrorCode(t, err, ErrLicenseNotActive)
}

func TestExpiredStatusRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeLicense(t, sk, makePayloadJSON("expired", nil, nil, nil))
	_, err := ActivateFromJSONOffline(license, pk)
	assertErrorCode(t, err, ErrLicenseNotActive)
}

func TestEmptyStatusRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeLicense(t, sk, makePayloadJSON("", nil, nil, nil))
	_, err := ActivateFromJSONOffline(license, pk)
	assertErrorCode(t, err, ErrLicenseNotActive)
}

func TestFutureExpiryAccepted(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicenseWithExpiry(t, sk, "2099-12-31T23:59:59Z")
	_, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPastExpiryRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicenseWithExpiry(t, sk, "2020-01-01T00:00:00Z")
	_, err := ActivateFromJSONOffline(license, pk)
	assertErrorCode(t, err, ErrLicenseExpired)
}

func TestNullExpiryAccepted(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)
	_, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExpiryDateFormatsAccepted(t *testing.T) {
	formats := []string{
		"2099-12-31T23:59:59Z",
		"2099-12-31T23:59:59+00:00",
		"2099-12-31T23:59:59-05:00",
		"2099-12-31T23:59:59.000Z",
		"2099-12-31T23:59:59.000000Z",
	}
	for _, f := range formats {
		t.Run(f, func(t *testing.T) {
			sk, pk := genKeypair(t)
			license := makeActiveLicenseWithExpiry(t, sk, f)
			_, err := ActivateFromJSONOffline(license, pk)
			if err != nil {
				t.Fatalf("format %q rejected: %v", f, err)
			}
		})
	}
}

func TestExpiryDateFormatsPastRejected(t *testing.T) {
	formats := []string{
		"2020-01-01T00:00:00Z",
		"2020-01-01T00:00:00+00:00",
		"2020-01-01T00:00:00.000Z",
	}
	for _, f := range formats {
		t.Run(f, func(t *testing.T) {
			sk, pk := genKeypair(t)
			license := makeActiveLicenseWithExpiry(t, sk, f)
			_, err := ActivateFromJSONOffline(license, pk)
			assertErrorCode(t, err, ErrLicenseExpired)
		})
	}
}

// ── Payload field tests ───────────────────────────────────────────

func TestAllowedFeaturesParsed(t *testing.T) {
	sk, pk := genKeypair(t)
	features := json.RawMessage(`{"pro":true,"max_users":100}`)
	license := makeActiveLicenseWithFeatures(t, sk, features)
	result, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	json.Unmarshal(result.License.AllowedFeatures, &f)
	if f["pro"] != true {
		t.Error("expected pro=true")
	}
	if f["max_users"] != float64(100) {
		t.Errorf("expected max_users=100, got %v", f["max_users"])
	}
}

func TestNullFeaturesAccepted(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)
	result, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.License.AllowedFeatures) != "null" && result.License.AllowedFeatures != nil {
		t.Errorf("expected null features, got %s", result.License.AllowedFeatures)
	}
}

func TestUsageLimitParsed(t *testing.T) {
	sk, pk := genKeypair(t)
	payloadStr := `{"license_id":"lic_test","product_id":"prod_test","customer_id":"cust_test","status":"active","expiry_date":null,"allowed_features":null,"usage_limit":5000,"token_ttl":null,"activation_url":null}`
	license := makeLicense(t, sk, payloadStr)
	result, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.UsageLimit == nil || *result.License.UsageLimit != 5000 {
		t.Errorf("expected usage_limit=5000, got %v", result.License.UsageLimit)
	}
}

func TestActivationURLParsed(t *testing.T) {
	sk, pk := genKeypair(t)
	payloadStr := makePayloadJSON("active", nil, strPtr("https://api.runlicense.com/activate"), nil)
	license := makeLicense(t, sk, payloadStr)
	payload, err := verifySignature(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if payload.ActivationURL == nil || *payload.ActivationURL != "https://api.runlicense.com/activate" {
		t.Errorf("unexpected activation_url: %v", payload.ActivationURL)
	}
}

// ── Full verification pipeline tests ──────────────────────────────

func TestFullPipelineValidLicense(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicenseWithExpiry(t, sk, "2099-12-31T23:59:59Z")
	result, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.Status != "active" {
		t.Error("expected active")
	}
	if result.License.ExpiryDate == nil || *result.License.ExpiryDate != "2099-12-31T23:59:59Z" {
		t.Error("unexpected expiry")
	}
}

func TestFullPipelineSignatureCheckedBeforeStatus(t *testing.T) {
	sk, _ := genKeypair(t)
	_, pk2 := genKeypair(t)
	license := makeActiveLicense(t, sk)
	_, err := ActivateFromJSONOffline(license, pk2)
	assertErrorCode(t, err, ErrSignatureMismatch)
}

func TestFullPipelineStatusCheckedBeforeExpiry(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeLicense(t, sk, makePayloadJSON("suspended", strPtr("2099-12-31T23:59:59Z"), nil, nil))
	_, err := ActivateFromJSONOffline(license, pk)
	assertErrorCode(t, err, ErrLicenseNotActive)
}

// ── License file discovery tests ──────────────────────────────────

func TestDiscoverNonexistentNamespace(t *testing.T) {
	_, err := discoverLicensePath("nonexistent/namespace")
	assertErrorCode(t, err, ErrLicenseFileNotFound)
}

func TestDiscoverViaEnvVar(t *testing.T) {
	dir := t.TempDir()
	ns := "testorg/testpkg"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte("{}"), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	path, err := discoverLicensePath(ns)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(licenseDir, "license.json") {
		t.Errorf("unexpected path: %s", path)
	}
}

func TestDiscoverViaCwd(t *testing.T) {
	dir := t.TempDir()
	ns := "testorg/testpkg"
	licenseDir := filepath.Join(dir, "runlicense", ns)
	os.MkdirAll(licenseDir, 0755)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte("{}"), 0644)

	// Save and restore CWD
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	t.Setenv("RUNLICENSE_DIR", "")
	_, err := discoverLicensePath(ns)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnvVarTakesPrecedenceOverCwd(t *testing.T) {
	envDir := t.TempDir()
	cwdDir := t.TempDir()
	ns := "testorg/testpkg"

	envLicenseDir := filepath.Join(envDir, ns)
	os.MkdirAll(envLicenseDir, 0755)
	os.WriteFile(filepath.Join(envLicenseDir, "license.json"), []byte(`{"source":"env"}`), 0644)

	cwdLicenseDir := filepath.Join(cwdDir, "runlicense", ns)
	os.MkdirAll(cwdLicenseDir, 0755)
	os.WriteFile(filepath.Join(cwdLicenseDir, "license.json"), []byte(`{"source":"cwd"}`), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(cwdDir)
	defer os.Chdir(origDir)

	t.Setenv("RUNLICENSE_DIR", envDir)
	path, err := discoverLicensePath(ns)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, envDir) {
		t.Errorf("expected path under env dir, got %s", path)
	}
}

func TestLoadAndVerifyLicenseFromDisk(t *testing.T) {
	sk, pk := genKeypair(t)
	licenseJSON := makeActiveLicense(t, sk)

	dir := t.TempDir()
	ns := "testorg/disktest"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte(licenseJSON), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	result, err := ActivateOffline(ns, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.LicenseID != "lic_test_123" {
		t.Errorf("unexpected license_id: %s", result.License.LicenseID)
	}
}

func TestLoadUnreadableNamespaceFails(t *testing.T) {
	_, pk := genKeypair(t)
	_, err := ActivateOffline("does/not/exist", pk)
	assertErrorCode(t, err, ErrLicenseFileNotFound)
}

// ── Nested namespace tests ────────────────────────────────────────

func TestDeeplyNestedNamespace(t *testing.T) {
	sk, pk := genKeypair(t)
	licenseJSON := makeActiveLicense(t, sk)

	dir := t.TempDir()
	ns := "org/team/subpkg"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte(licenseJSON), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	_, err := ActivateOffline(ns, pk)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMultipleNamespacesCoexist(t *testing.T) {
	sk1, pk1 := genKeypair(t)
	sk2, pk2 := genKeypair(t)

	license1 := makeActiveLicense(t, sk1)
	payload2Str := `{"license_id":"lic_other","product_id":"prod_other","customer_id":"cust_other","status":"active","expiry_date":null,"allowed_features":null,"usage_limit":null,"token_ttl":null,"activation_url":null}`
	license2 := makeLicense(t, sk2, payload2Str)

	r1, err := ActivateFromJSONOffline(license1, pk1)
	if err != nil {
		t.Fatal(err)
	}
	if r1.License.LicenseID != "lic_test_123" {
		t.Error("wrong license_id for license1")
	}

	r2, err := ActivateFromJSONOffline(license2, pk2)
	if err != nil {
		t.Fatal(err)
	}
	if r2.License.LicenseID != "lic_other" {
		t.Error("wrong license_id for license2")
	}

	// Cross-key should fail
	_, err = ActivateFromJSONOffline(license1, pk2)
	assertErrorCode(t, err, ErrSignatureMismatch)
	_, err = ActivateFromJSONOffline(license2, pk1)
	assertErrorCode(t, err, ErrSignatureMismatch)
}

func TestWrongKeyForNamespaceRejected(t *testing.T) {
	sk1, _ := genKeypair(t)
	_, pk2 := genKeypair(t)
	licenseJSON := makeActiveLicense(t, sk1)

	dir := t.TempDir()
	ns := "testorg/wrongkey"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte(licenseJSON), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	_, err := ActivateOffline(ns, pk2)
	assertErrorCode(t, err, ErrSignatureMismatch)
}

// ── Error display tests ───────────────────────────────────────────

func TestErrorDisplayMessages(t *testing.T) {
	tests := []struct {
		err      *LicenseError
		contains string
	}{
		{&LicenseError{Code: ErrLicenseFileNotFound, Message: "some/path"}, "some/path"},
		{&LicenseError{Code: ErrSignatureMismatch}, "signature verification failed"},
		{&LicenseError{Code: ErrLicenseNotActive, Message: "revoked"}, "revoked"},
		{&LicenseError{Code: ErrLicenseExpired, Message: "2024-01-01T00:00:00Z"}, "2024-01-01"},
	}
	for _, tc := range tests {
		msg := tc.err.Error()
		if !strings.Contains(msg, tc.contains) {
			t.Errorf("error message %q does not contain %q", msg, tc.contains)
		}
	}
}

func TestErrorImplementsErrorInterface(t *testing.T) {
	var err error = &LicenseError{Code: ErrInvalidPublicKey}
	if err.Error() != "invalid public key" {
		t.Errorf("unexpected: %s", err.Error())
	}
}

func TestErrorsAsLicenseError(t *testing.T) {
	var err error = &LicenseError{Code: ErrLicenseExpired, Message: "2024-01-01"}
	var licErr *LicenseError
	if !errors.As(err, &licErr) {
		t.Fatal("errors.As failed")
	}
	if licErr.Code != ErrLicenseExpired {
		t.Error("wrong code")
	}
}

// ── Validation token tests ────────────────────────────────────────

func TestValidTokenAccepted(t *testing.T) {
	sk, pk := genKeypair(t)
	nonce := "abc123"
	licenseID := "lic_test_123"
	tokenStr := makeValidationToken(t, sk, licenseID, nonce, "2099-12-31T23:59:59Z")
	token, err := verifyToken(tokenStr, pk, nonce, licenseID)
	if err != nil {
		t.Fatal(err)
	}
	if token.LicenseID != licenseID {
		t.Error("wrong license_id")
	}
	if token.Nonce != nonce {
		t.Error("wrong nonce")
	}
}

func TestTokenWrongSignatureRejected(t *testing.T) {
	sk, _ := genKeypair(t)
	_, pk2 := genKeypair(t)
	tokenStr := makeValidationToken(t, sk, "lic_test", "nonce1", "2099-12-31T23:59:59Z")
	_, err := verifyToken(tokenStr, pk2, "nonce1", "lic_test")
	assertErrorCode(t, err, ErrInvalidValidationToken)
}

func TestTokenNonceMismatchRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	tokenStr := makeValidationToken(t, sk, "lic_test", "correct_nonce", "2099-12-31T23:59:59Z")
	_, err := verifyToken(tokenStr, pk, "wrong_nonce", "lic_test")
	assertErrorCode(t, err, ErrValidationTokenNonceMismatch)
}

func TestTokenLicenseIDMismatchRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	tokenStr := makeValidationToken(t, sk, "lic_original", "nonce1", "2099-12-31T23:59:59Z")
	_, err := verifyToken(tokenStr, pk, "nonce1", "lic_different")
	assertErrorCode(t, err, ErrValidationTokenLicenseMismatch)
}

func TestExpiredTokenRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	tokenStr := makeValidationToken(t, sk, "lic_test", "nonce1", "2020-01-01T00:00:00Z")
	_, err := verifyToken(tokenStr, pk, "nonce1", "lic_test")
	assertErrorCode(t, err, ErrValidationTokenExpired)
}

func TestMalformedTokenRejected(t *testing.T) {
	_, pk := genKeypair(t)

	// No dot separator
	_, err := verifyToken("nodot", pk, "n", "l")
	assertErrorCode(t, err, ErrInvalidValidationToken)

	// Invalid base64
	_, err = verifyToken("!!!.!!!", pk, "n", "l")
	assertErrorCode(t, err, ErrInvalidValidationToken)

	// Valid base64 but not a valid token payload
	payload := base64.StdEncoding.EncodeToString([]byte("notjson"))
	sig := base64.StdEncoding.EncodeToString([]byte("notsig"))
	_, err = verifyToken(payload+"."+sig, pk, "n", "l")
	assertErrorCode(t, err, ErrInvalidValidationToken)
}

func TestTokenExpiryDateFormats(t *testing.T) {
	formats := []string{
		"2099-12-31T23:59:59Z",
		"2099-12-31T23:59:59+00:00",
		"2099-12-31T23:59:59.000Z",
	}
	for _, f := range formats {
		t.Run(f, func(t *testing.T) {
			sk, pk := genKeypair(t)
			tokenStr := makeValidationToken(t, sk, "lic_test", "nonce1", f)
			_, err := verifyToken(tokenStr, pk, "nonce1", "lic_test")
			if err != nil {
				t.Fatalf("format %q rejected: %v", f, err)
			}
		})
	}
}

// ── Token caching tests ──────────────────────────────────────────

func TestCacheAndLoadSignedToken(t *testing.T) {
	sk, pk := genKeypair(t)
	dir := t.TempDir()
	licenseID := "lic_cache_test"
	rawToken := makeValidationToken(t, sk, licenseID, "nonce123", "2099-12-31T23:59:59Z")

	cacheToken(dir, rawToken)
	loaded := loadCachedToken(dir, pk, licenseID)
	if loaded == nil {
		t.Fatal("expected cached token")
	}
	if loaded.LicenseID != licenseID {
		t.Error("wrong license_id")
	}
}

func TestLoadMissingCachedTokenReturnsNil(t *testing.T) {
	_, pk := genKeypair(t)
	dir := t.TempDir()
	loaded := loadCachedToken(dir, pk, "lic_test")
	if loaded != nil {
		t.Error("expected nil")
	}
}

func TestLoadCorruptCachedTokenReturnsNil(t *testing.T) {
	_, pk := genKeypair(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".runlicense_token"), []byte("not valid data"), 0600)
	loaded := loadCachedToken(dir, pk, "lic_test")
	if loaded != nil {
		t.Error("expected nil")
	}
}

func TestForgedUnsignedCachedTokenRejected(t *testing.T) {
	_, pk := genKeypair(t)
	dir := t.TempDir()
	forged, _ := json.Marshal(map[string]string{
		"license_id": "lic_stolen",
		"nonce":      "fake",
		"issued_at":  "2025-01-01T00:00:00Z",
		"expires_at": "2099-12-31T23:59:59Z",
	})
	os.WriteFile(filepath.Join(dir, ".runlicense_token"), forged, 0600)
	loaded := loadCachedToken(dir, pk, "lic_stolen")
	if loaded != nil {
		t.Error("expected nil for forged token")
	}
}

func TestCachedTokenWrongKeyRejected(t *testing.T) {
	sk, _ := genKeypair(t)
	_, pk2 := genKeypair(t)
	dir := t.TempDir()
	rawToken := makeValidationToken(t, sk, "lic_test", "nonce1", "2099-12-31T23:59:59Z")

	cacheToken(dir, rawToken)
	loaded := loadCachedToken(dir, pk2, "lic_test")
	if loaded != nil {
		t.Error("expected nil for wrong key")
	}
}

func TestCachedTokenWrongLicenseIDRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	dir := t.TempDir()
	rawToken := makeValidationToken(t, sk, "lic_original", "nonce1", "2099-12-31T23:59:59Z")

	cacheToken(dir, rawToken)
	loaded := loadCachedToken(dir, pk, "lic_different")
	if loaded != nil {
		t.Error("expected nil for wrong license_id")
	}
}

func TestCachedTokenExpiredRejected(t *testing.T) {
	sk, pk := genKeypair(t)
	dir := t.TempDir()
	rawToken := makeValidationToken(t, sk, "lic_test", "nonce1", "2020-01-01T00:00:00Z")

	cacheToken(dir, rawToken)
	loaded := loadCachedToken(dir, pk, "lic_test")
	if loaded != nil {
		t.Error("expected nil for expired token")
	}
}

func TestCacheOverwritesPreviousToken(t *testing.T) {
	sk, pk := genKeypair(t)
	dir := t.TempDir()

	raw1 := makeValidationToken(t, sk, "lic_first", "n1", "2099-01-01T00:00:00Z")
	cacheToken(dir, raw1)

	raw2 := makeValidationToken(t, sk, "lic_second", "n2", "2099-06-01T00:00:00Z")
	cacheToken(dir, raw2)

	loaded := loadCachedToken(dir, pk, "lic_second")
	if loaded == nil || loaded.LicenseID != "lic_second" {
		t.Error("expected second token")
	}

	loadedOld := loadCachedToken(dir, pk, "lic_first")
	if loadedOld != nil {
		t.Error("expected nil for overwritten token")
	}
}

// ── Atomic cache write test ──────────────────────────────────────

func TestCacheTokenAtomicWrite(t *testing.T) {
	sk, pk := genKeypair(t)
	dir := t.TempDir()
	rawToken := makeValidationToken(t, sk, "lic_test", "nonce1", "2099-12-31T23:59:59Z")

	cacheToken(dir, rawToken)

	// Verify no .tmp file left behind
	tmpPath := filepath.Join(dir, ".runlicense_token.tmp")
	if _, err := os.Stat(tmpPath); err == nil {
		t.Error(".tmp file should not exist after successful cache")
	}

	// Verify the actual file exists and is valid
	loaded := loadCachedToken(dir, pk, "lic_test")
	if loaded == nil {
		t.Fatal("expected cached token")
	}
}

// ── Namespace validation tests ────────────────────────────────────

func TestNamespacePathTraversalRejected(t *testing.T) {
	_, err := discoverLicensePath("../../etc")
	assertErrorCode(t, err, ErrLicenseFileNotFound)
	var licErr *LicenseError
	errors.As(err, &licErr)
	if !strings.Contains(licErr.Message, "invalid namespace") {
		t.Errorf("expected 'invalid namespace' in message, got: %s", licErr.Message)
	}
}

func TestNamespaceDotComponentRejected(t *testing.T) {
	_, err := discoverLicensePath("org/./pkg")
	assertErrorCode(t, err, ErrLicenseFileNotFound)
}

func TestNamespaceDoubleDotRejected(t *testing.T) {
	_, err := discoverLicensePath("org/../other")
	assertErrorCode(t, err, ErrLicenseFileNotFound)
}

func TestNamespaceEmptySegmentRejected(t *testing.T) {
	_, err := discoverLicensePath("org//pkg")
	assertErrorCode(t, err, ErrLicenseFileNotFound)
}

func TestNamespaceBackslashRejected(t *testing.T) {
	_, err := discoverLicensePath(`org\..\secret`)
	assertErrorCode(t, err, ErrLicenseFileNotFound)
	var licErr *LicenseError
	errors.As(err, &licErr)
	if !strings.Contains(licErr.Message, "backslash") {
		t.Errorf("expected 'backslash' in message, got: %s", licErr.Message)
	}
}

func TestNamespaceValidFormatsAccepted(t *testing.T) {
	namespaces := []string{"myorg/mypkg", "org/team/subpkg", "simple"}
	for _, ns := range namespaces {
		t.Run(ns, func(t *testing.T) {
			_, err := discoverLicensePath(ns)
			assertErrorCode(t, err, ErrLicenseFileNotFound)
			var licErr *LicenseError
			errors.As(err, &licErr)
			if strings.Contains(licErr.Message, "invalid namespace") {
				t.Error("valid namespace was rejected as invalid")
			}
		})
	}
}

// ── Edge case tests ───────────────────────────────────────────────

func TestEmptyLicenseJSONRejected(t *testing.T) {
	_, pk := genKeypair(t)
	_, err := ActivateFromJSONOffline("", pk)
	assertErrorCode(t, err, ErrInvalidJSON)
}

func TestEmptyObjectRejected(t *testing.T) {
	_, pk := genKeypair(t)
	_, err := verifySignature("{}", pk)
	// Empty signature field will fail to decode
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnicodeInPayloadFields(t *testing.T) {
	sk, pk := genKeypair(t)
	payloadStr := `{"license_id":"lic_test","product_id":"prod_unicode","customer_id":"cust_test","status":"active","expiry_date":null,"allowed_features":{"name":"Acme Corp™"},"usage_limit":null,"token_ttl":null,"activation_url":null}`
	license := makeLicense(t, sk, payloadStr)
	result, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.ProductID != "prod_unicode" {
		t.Error("wrong product_id")
	}
}

func TestLargeFeatureObject(t *testing.T) {
	sk, pk := genKeypair(t)
	features := make(map[string]bool)
	for i := 0; i < 100; i++ {
		features[fmt.Sprintf("feature_%d", i)] = i%2 == 0
	}
	featJSON, _ := json.Marshal(features)
	license := makeActiveLicenseWithFeatures(t, sk, json.RawMessage(featJSON))
	result, err := ActivateFromJSONOffline(license, pk)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]bool
	json.Unmarshal(result.License.AllowedFeatures, &f)
	if len(f) != 100 {
		t.Errorf("expected 100 features, got %d", len(f))
	}
}

func TestDeterministicSigning(t *testing.T) {
	sk, pk := genKeypair(t)
	payloadStr := makePayloadJSON("active", nil, nil, nil)
	license1 := makeLicense(t, sk, payloadStr)
	license2 := makeLicense(t, sk, payloadStr)
	if license1 != license2 {
		t.Error("deterministic signing should produce identical licenses")
	}
	if _, err := verifySignature(license1, pk); err != nil {
		t.Fatal(err)
	}
}

func TestDifferentKeysProduceDifferentSignatures(t *testing.T) {
	sk1, _ := genKeypair(t)
	sk2, _ := genKeypair(t)
	payloadStr := makePayloadJSON("active", nil, nil, nil)
	license1 := makeLicense(t, sk1, payloadStr)
	license2 := makeLicense(t, sk2, payloadStr)
	if license1 == license2 {
		t.Error("different keys should produce different signatures")
	}
}

// ── Phone-home integration tests ──────────────────────────────────

func TestActivateWithPhoneHome(t *testing.T) {
	sk, pk := genKeypair(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Nonce          string `json:"nonce"`
			NonceSignature string `json:"nonce_signature"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		tokenStr := makeValidationToken(t, sk, "lic_test_123", req.Nonce, "2099-12-31T23:59:59Z")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"token": tokenStr, "expires_at": "2099-12-31T23:59:59Z", "activations_remaining": 9995}})
	}))
	defer server.Close()

	payloadStr := makePayloadJSON("active", strPtr("2099-12-31T23:59:59Z"), strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)

	result, err := ActivateFromJSON(context.Background(), license, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.LicenseID != "lic_test_123" {
		t.Error("wrong license_id")
	}
	if result.ActivationsRemaining != 9995 {
		t.Errorf("expected activations_remaining=9995, got %d", result.ActivationsRemaining)
	}
	if result.ExpiresAt != "2099-12-31T23:59:59Z" {
		t.Errorf("expected expires_at=2099-12-31T23:59:59Z, got %s", result.ExpiresAt)
	}
}

func TestActivatePhoneHomeServerRejects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("license revoked"))
	}))
	defer server.Close()

	sk, pk := genKeypair(t)
	payloadStr := makePayloadJSON("active", nil, strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)

	_, err := ActivateFromJSON(context.Background(), license, pk)
	assertErrorCode(t, err, ErrServerRejected)
}

func TestActivatePhoneHomeInvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"token": "invalid.token"}})
	}))
	defer server.Close()

	sk, pk := genKeypair(t)
	payloadStr := makePayloadJSON("active", nil, strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)

	_, err := ActivateFromJSON(context.Background(), license, pk)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestActivatePhoneHomeContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	sk, pk := genKeypair(t)
	payloadStr := makePayloadJSON("active", nil, strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := ActivateFromJSON(ctx, license, pk)
	assertErrorCode(t, err, ErrPhoneHomeFailed)
}

func TestActivateWithGracePeriod(t *testing.T) {
	sk, pk := genKeypair(t)

	dir := t.TempDir()
	ns := "testorg/gracepkg"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)

	// Pre-cache a valid token
	rawToken := makeValidationToken(t, sk, "lic_test_123", "old_nonce", "2099-12-31T23:59:59Z")
	cacheToken(licenseDir, rawToken)

	// Server that's down
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	payloadStr := makePayloadJSON("active", nil, strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte(license), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	result, err := Activate(context.Background(), ns, pk)
	if err != nil {
		t.Fatalf("grace period should have succeeded: %v", err)
	}
	if result.License.LicenseID != "lic_test_123" {
		t.Error("wrong license_id")
	}
}

func TestActivateNoGracePeriodWithoutCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sk, pk := genKeypair(t)
	dir := t.TempDir()
	ns := "testorg/nograce"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)

	payloadStr := makePayloadJSON("active", nil, strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte(license), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	_, err := Activate(context.Background(), ns, pk)
	if err == nil {
		t.Fatal("expected failure without cached token")
	}
}

// ── parseExpiryDate tests ─────────────────────────────────────────

func TestParseExpiryDateFormats(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"2025-06-15T12:00:00Z", true},
		{"2025-06-15T12:00:00+00:00", true},
		{"2025-06-15T12:00:00-05:00", true},
		{"2025-06-15T12:00:00.000Z", true},
		{"2025-06-15T12:00:00.000000Z", true},
		{"not a date", false},
		{"2025-13-01T00:00:00Z", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := parseExpiryDate(tc.input)
			if tc.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Error("expected error for invalid date")
			}
		})
	}
}

// ── Nonce generation test ─────────────────────────────────────────

func TestGenerateNonceUnique(t *testing.T) {
	n1, err := generateNonce()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := generateNonce()
	if err != nil {
		t.Fatal(err)
	}
	if n1 == n2 {
		t.Error("nonces should be unique")
	}
	if len(n1) != 32 { // 16 bytes hex-encoded = 32 chars
		t.Errorf("expected 32 char nonce, got %d", len(n1))
	}
}

// ── HMAC nonce signing test ───────────────────────────────────────

func TestSignNonceDeterministic(t *testing.T) {
	_, pk := genKeypair(t)
	sig1, err := signNonce("testnonce", pk)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := signNonce("testnonce", pk)
	if err != nil {
		t.Fatal(err)
	}
	if sig1 != sig2 {
		t.Error("HMAC should be deterministic")
	}
}

func TestSignNonceDifferentInputs(t *testing.T) {
	_, pk := genKeypair(t)
	sig1, _ := signNonce("nonce1", pk)
	sig2, _ := signNonce("nonce2", pk)
	if sig1 == sig2 {
		t.Error("different nonces should produce different signatures")
	}
}

func TestSignNonceInvalidKey(t *testing.T) {
	_, err := signNonce("test", "!!!invalid!!!")
	assertErrorCode(t, err, ErrInvalidPublicKey)
}

// ── SetLicenseJSON override tests ─────────────────────────────────

func TestSetLicenseJSONOverridesFileDiscovery(t *testing.T) {
	sk, pk := genKeypair(t)
	license := makeActiveLicense(t, sk)

	ns := "testorg/embedded"
	SetLicenseJSON(ns, license)
	defer func() {
		licenseOverridesMu.Lock()
		delete(licenseOverrides, ns)
		licenseOverridesMu.Unlock()
	}()

	// Should succeed without any license file on disk
	result, err := ActivateOffline(ns, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.LicenseID != "lic_test_123" {
		t.Errorf("unexpected license_id: %s", result.License.LicenseID)
	}
}

func TestSetLicenseJSONWithPhoneHome(t *testing.T) {
	sk, pk := genKeypair(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Nonce string `json:"nonce"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		tokenStr := makeValidationToken(t, sk, "lic_test_123", req.Nonce, "2099-12-31T23:59:59Z")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"token": tokenStr, "expires_at": "2099-12-31T23:59:59Z", "activations_remaining": 9995}})
	}))
	defer server.Close()

	payloadStr := makePayloadJSON("active", nil, strPtr(server.URL), nil)
	license := makeLicense(t, sk, payloadStr)

	ns := "testorg/embedded-phonehome"
	SetLicenseJSON(ns, license)
	defer func() {
		licenseOverridesMu.Lock()
		delete(licenseOverrides, ns)
		licenseOverridesMu.Unlock()
	}()

	result, err := Activate(context.Background(), ns, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.LicenseID != "lic_test_123" {
		t.Error("wrong license_id")
	}
}

func TestSetLicenseJSONInvalidLicenseStillFails(t *testing.T) {
	_, pk := genKeypair(t)

	ns := "testorg/bad-embedded"
	SetLicenseJSON(ns, "not valid json")
	defer func() {
		licenseOverridesMu.Lock()
		delete(licenseOverrides, ns)
		licenseOverridesMu.Unlock()
	}()

	_, err := ActivateOffline(ns, pk)
	assertErrorCode(t, err, ErrInvalidJSON)
}

func TestSetLicenseJSONWrongKeyStillFails(t *testing.T) {
	sk, _ := genKeypair(t)
	_, pk2 := genKeypair(t)
	license := makeActiveLicense(t, sk)

	ns := "testorg/wrongkey-embedded"
	SetLicenseJSON(ns, license)
	defer func() {
		licenseOverridesMu.Lock()
		delete(licenseOverrides, ns)
		licenseOverridesMu.Unlock()
	}()

	_, err := ActivateOffline(ns, pk2)
	assertErrorCode(t, err, ErrSignatureMismatch)
}

func TestNoOverrideFallsBackToFileDiscovery(t *testing.T) {
	sk, pk := genKeypair(t)
	licenseJSON := makeActiveLicense(t, sk)

	dir := t.TempDir()
	ns := "testorg/fallback"
	licenseDir := filepath.Join(dir, ns)
	os.MkdirAll(licenseDir, 0755)
	os.WriteFile(filepath.Join(licenseDir, "license.json"), []byte(licenseJSON), 0644)

	t.Setenv("RUNLICENSE_DIR", dir)
	// No override set — should discover from disk
	result, err := ActivateOffline(ns, pk)
	if err != nil {
		t.Fatal(err)
	}
	if result.License.LicenseID != "lic_test_123" {
		t.Error("wrong license_id")
	}
}
