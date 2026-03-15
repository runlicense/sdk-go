package runlicense

import "fmt"

// LicenseError represents errors that can occur during license verification.
type LicenseError struct {
	Code    ErrorCode
	Message string
}

// ErrorCode identifies the specific type of license error.
type ErrorCode int

const (
	ErrLicenseFileNotFound            ErrorCode = iota // Could not find the license file
	ErrLicenseFileUnreadable                           // Could not read the license file
	ErrInvalidJSON                                     // The license JSON is malformed
	ErrInvalidPublicKey                                // The public key is invalid
	ErrInvalidSignature                                // The signature encoding is invalid
	ErrSignatureMismatch                               // Signature does not match payload
	ErrLicenseNotActive                                // License status is not "active"
	ErrLicenseExpired                                  // License has expired
	ErrNoActivationURL                                 // No activation URL for phone-home
	ErrPhoneHomeFailed                                 // Phone-home request failed
	ErrInvalidValidationToken                          // Validation token from server is invalid
	ErrValidationTokenNonceMismatch                    // Nonce in validation token does not match
	ErrValidationTokenExpired                          // Validation token has expired
	ErrValidationTokenLicenseMismatch                  // License ID in validation token does not match
	ErrServerRejected                                  // Server rejected the license
)

func (e *LicenseError) Error() string {
	switch e.Code {
	case ErrLicenseFileNotFound:
		return fmt.Sprintf("license file not found: %s", e.Message)
	case ErrLicenseFileUnreadable:
		return fmt.Sprintf("could not read license file: %s", e.Message)
	case ErrInvalidJSON:
		return fmt.Sprintf("invalid license JSON: %s", e.Message)
	case ErrInvalidPublicKey:
		return "invalid public key"
	case ErrInvalidSignature:
		return "invalid signature encoding"
	case ErrSignatureMismatch:
		return "signature verification failed — license may be tampered"
	case ErrLicenseNotActive:
		return fmt.Sprintf("license is not active (status: %s)", e.Message)
	case ErrLicenseExpired:
		return fmt.Sprintf("license expired on %s", e.Message)
	case ErrNoActivationURL:
		return "no activation URL configured for phone-home"
	case ErrPhoneHomeFailed:
		return fmt.Sprintf("phone-home validation failed: %s", e.Message)
	case ErrInvalidValidationToken:
		return "invalid validation token from server"
	case ErrValidationTokenNonceMismatch:
		return "validation token nonce mismatch — possible replay attack"
	case ErrValidationTokenExpired:
		return "validation token has expired"
	case ErrValidationTokenLicenseMismatch:
		return "validation token license ID mismatch"
	case ErrServerRejected:
		return fmt.Sprintf("server rejected license: %s", e.Message)
	default:
		return e.Message
	}
}
