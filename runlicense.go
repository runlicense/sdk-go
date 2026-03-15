// Package runlicense provides license verification for Go applications
// using the RunLicense system.
//
// # Quick Start
//
//  1. Embed your RunLicense public key in your application.
//  2. Your end users place their license at runlicense/<namespace>/license.json.
//  3. Call Activate at startup.
//
// Example:
//
//	import (
//	    _ "embed"
//	    runlicense "github.com/runlicense/sdk-go"
//	)
//
//	//go:embed keys/runlicense.key
//	var publicKey string
//
//	func init() {
//	    license, err := runlicense.Activate(context.Background(), "myorg/mypackage", publicKey)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Println("Licensed to customer:", license.CustomerID)
//	}
//
// # License File Discovery
//
// The SDK searches for runlicense/<namespace>/license.json in:
//  1. RUNLICENSE_DIR environment variable (if set)
//  2. The directory containing the running executable
//  3. The current working directory
//
// # Phone-Home Validation
//
// By default, Activate performs server-side phone-home validation in addition
// to offline signature and expiry checks. To disable phone-home, use
// ActivateOffline instead.
package runlicense

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// licenseOverrides stores embedded license JSON keyed by namespace.
// Application developers call SetLicenseJSON to register these before
// package init() functions call Activate.
var (
	licenseOverrides   = make(map[string]string)
	licenseOverridesMu sync.RWMutex
)

// SetLicenseJSON registers an embedded license JSON string for a namespace.
// When Activate or ActivateOffline is called for this namespace, the
// registered JSON is used instead of searching the filesystem.
//
// This enables single-binary distribution: application developers embed
// the license file at compile time and register it before licensed packages
// initialize.
//
// Example:
//
//	//go:embed runlicense/acme/image-processor/license.json
//	var licenseJSON string
//
//	func init() {
//	    runlicense.SetLicenseJSON("acme/image-processor", licenseJSON)
//	}
func SetLicenseJSON(namespace, licenseJSON string) {
	licenseOverridesMu.Lock()
	defer licenseOverridesMu.Unlock()
	licenseOverrides[namespace] = licenseJSON
}

// Activate verifies a license by namespace with full phone-home validation.
//
// It discovers the license file at runlicense/<namespace>/license.json,
// verifies the Ed25519 signature, checks that the license is active and not
// expired, and performs phone-home validation with the activation server.
//
// The publicKeyB64 parameter should contain the base64-encoded Ed25519
// public key. Use Go's embed directive to embed this from keys/runlicense.key.
//
// The context controls the phone-home HTTP request timeout and cancellation.
func Activate(ctx context.Context, namespace, publicKeyB64 string) (*LicensePayload, error) {
	// Check for embedded license override
	licenseOverridesMu.RLock()
	override, hasOverride := licenseOverrides[namespace]
	licenseOverridesMu.RUnlock()

	if hasOverride {
		return ActivateFromJSON(ctx, override, publicKeyB64)
	}

	jsonData, licensePath, err := loadLicenseFile(namespace)
	if err != nil {
		return nil, err
	}

	payload, err := verifySignature(jsonData, publicKeyB64)
	if err != nil {
		return nil, err
	}

	if err := verifyStatusAndExpiry(payload); err != nil {
		return nil, err
	}

	if payload.ActivationURL != nil {
		cacheDir := filepath.Dir(licensePath)
		_, rawToken, err := phoneHome(ctx, payload, publicKeyB64)
		if err == nil {
			cacheToken(cacheDir, rawToken)
		} else {
			// Grace period: try cached token
			if loadCachedToken(cacheDir, publicKeyB64, payload.LicenseID) != nil {
				return payload, nil
			}
			return nil, err
		}
	}

	return payload, nil
}

// ActivateOffline verifies a license by namespace without phone-home validation.
//
// It performs offline signature and expiry checks only.
// No network calls are made, so no context is required.
func ActivateOffline(namespace, publicKeyB64 string) (*LicensePayload, error) {
	// Check for embedded license override
	licenseOverridesMu.RLock()
	override, hasOverride := licenseOverrides[namespace]
	licenseOverridesMu.RUnlock()

	if hasOverride {
		return ActivateFromJSONOffline(override, publicKeyB64)
	}

	jsonData, _, err := loadLicenseFile(namespace)
	if err != nil {
		return nil, err
	}

	payload, err := verifySignature(jsonData, publicKeyB64)
	if err != nil {
		return nil, err
	}

	if err := verifyStatusAndExpiry(payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// ActivateFromJSON verifies a license from a JSON string directly.
//
// Use this when you already have the license JSON (e.g., loaded from a custom
// location or received from an API). Performs the same verification as Activate
// including phone-home, but without filesystem-based token caching.
//
// Note: because there is no license file path, no validation token is cached.
// This means there is no grace period — if phone-home fails, activation fails
// immediately. Use ActivateFromJSONOffline if you need offline-only verification.
func ActivateFromJSON(ctx context.Context, licenseJSON, publicKeyB64 string) (*LicensePayload, error) {
	payload, err := verifySignature(licenseJSON, publicKeyB64)
	if err != nil {
		return nil, err
	}

	if err := verifyStatusAndExpiry(payload); err != nil {
		return nil, err
	}

	if payload.ActivationURL != nil {
		if _, _, err := phoneHome(ctx, payload, publicKeyB64); err != nil {
			return nil, err
		}
	}

	return payload, nil
}

// ActivateFromJSONOffline verifies a license from a JSON string without
// phone-home validation.
func ActivateFromJSONOffline(licenseJSON, publicKeyB64 string) (*LicensePayload, error) {
	payload, err := verifySignature(licenseJSON, publicKeyB64)
	if err != nil {
		return nil, err
	}

	if err := verifyStatusAndExpiry(payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// validateNamespace checks that a namespace doesn't contain path traversal.
func validateNamespace(namespace string) error {
	if strings.ContainsRune(namespace, '\\') {
		return &LicenseError{
			Code:    ErrLicenseFileNotFound,
			Message: fmt.Sprintf("invalid namespace '%s': must not contain backslashes", namespace),
		}
	}
	for _, component := range strings.Split(namespace, "/") {
		if component == ".." || component == "." || component == "" {
			return &LicenseError{
				Code:    ErrLicenseFileNotFound,
				Message: fmt.Sprintf("invalid namespace '%s': must not contain '..' or '.' components or empty segments", namespace),
			}
		}
	}
	return nil
}

// discoverLicensePath finds the license file for a given namespace.
func discoverLicensePath(namespace string) (string, error) {
	if err := validateNamespace(namespace); err != nil {
		return "", err
	}

	relative := filepath.Join("runlicense", namespace, "license.json")

	// 1. Check RUNLICENSE_DIR env var
	if dir := os.Getenv("RUNLICENSE_DIR"); dir != "" {
		path := filepath.Join(dir, namespace, "license.json")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// 2. Check relative to executable directory
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		path := filepath.Join(exeDir, relative)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// 3. Check relative to current working directory
	if cwd, err := os.Getwd(); err == nil {
		path := filepath.Join(cwd, relative)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", &LicenseError{
		Code: ErrLicenseFileNotFound,
		Message: fmt.Sprintf(
			"searched for runlicense/%s/license.json in RUNLICENSE_DIR, executable directory, and working directory",
			namespace,
		),
	}
}

// maxLicenseFileSize is the maximum size of a license.json file (1 MB).
const maxLicenseFileSize = 1 << 20

// loadLicenseFile discovers and reads the license file.
func loadLicenseFile(namespace string) (string, string, error) {
	path, err := discoverLicensePath(namespace)
	if err != nil {
		return "", "", err
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", "", &LicenseError{
			Code:    ErrLicenseFileUnreadable,
			Message: err.Error(),
		}
	}
	if info.Size() > maxLicenseFileSize {
		return "", "", &LicenseError{
			Code:    ErrLicenseFileUnreadable,
			Message: fmt.Sprintf("license file too large (%d bytes, max %d)", info.Size(), maxLicenseFileSize),
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", &LicenseError{
			Code:    ErrLicenseFileUnreadable,
			Message: err.Error(),
		}
	}

	return string(data), path, nil
}

// verifySignature verifies the Ed25519 signature of a license payload.
func verifySignature(licenseJSON, publicKeyB64 string) (*LicensePayload, error) {
	// Parse the license file envelope
	var lf licenseFile
	if err := json.Unmarshal([]byte(licenseJSON), &lf); err != nil {
		return nil, &LicenseError{Code: ErrInvalidJSON, Message: err.Error()}
	}

	// Decode the public key
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, &LicenseError{Code: ErrInvalidPublicKey}
	}
	pubKey := ed25519.PublicKey(keyBytes)

	// Decode the signature
	sigBytes, err := base64.StdEncoding.DecodeString(lf.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, &LicenseError{Code: ErrInvalidSignature}
	}

	// Verify
	if !ed25519.Verify(pubKey, []byte(lf.Payload), sigBytes) {
		return nil, &LicenseError{Code: ErrSignatureMismatch}
	}

	// Parse the payload
	var payload LicensePayload
	if err := json.Unmarshal([]byte(lf.Payload), &payload); err != nil {
		return nil, &LicenseError{Code: ErrInvalidJSON, Message: fmt.Sprintf("payload: %s", err.Error())}
	}

	return &payload, nil
}

// parseExpiryDate parses an expiry date string in ISO 8601 / RFC 3339 format.
// Supports both "Z" and "+HH:MM" timezone offsets, with or without fractional seconds.
func parseExpiryDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognized date format: %s", s)
}

// verifyStatusAndExpiry checks that the license is active and not expired.
func verifyStatusAndExpiry(payload *LicensePayload) error {
	if payload.Status != "active" {
		return &LicenseError{Code: ErrLicenseNotActive, Message: payload.Status}
	}

	if payload.ExpiryDate != nil {
		expiry, err := parseExpiryDate(*payload.ExpiryDate)
		if err != nil {
			return &LicenseError{Code: ErrLicenseExpired, Message: *payload.ExpiryDate}
		}
		if time.Now().UTC().After(expiry.UTC()) {
			return &LicenseError{Code: ErrLicenseExpired, Message: *payload.ExpiryDate}
		}
	}

	return nil
}
