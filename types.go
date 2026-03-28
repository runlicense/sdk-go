package runlicense

import "encoding/json"

// LicensePayload contains the decoded license details returned on successful
// verification. Use AllowedFeatures for feature gating and UsageLimit as
// informational metadata (usage enforcement is application-level).
type LicensePayload struct {
	LicenseID       string          `json:"license_id"`
	ProductID       string          `json:"product_id"`
	CustomerID      string          `json:"customer_id"`
	Status          string          `json:"status"`
	ExpiryDate      *string         `json:"expiry_date"`
	AllowedFeatures json.RawMessage `json:"allowed_features"`
	UsageLimit      *uint64         `json:"usage_limit"`
	TokenTTL        *uint64         `json:"token_ttl"`
	ActivationURL   *string         `json:"activation_url"`
}

// ActivationResult is returned by all Activate functions. It always contains
// the verified LicensePayload. When phone-home validation was performed, the
// activation-specific fields (ExpiresAt, ActivationsRemaining) are also populated.
type ActivationResult struct {
	License              *LicensePayload
	ExpiresAt            string `json:"expires_at"`
	ActivationsRemaining int    `json:"activations_remaining"`
}

// ValidationToken is a signed validation token returned by the phone-home server.
type ValidationToken struct {
	LicenseID string `json:"license_id"`
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

// licenseFile is the outer license file structure containing a signed payload.
type licenseFile struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
