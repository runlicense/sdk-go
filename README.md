# RunLicense SDK for Go

License verification SDK for Go packages using the [RunLicense](https://runlicense.com) system.

## Overview

The RunLicense Go SDK lets package developers add license verification to their libraries. It handles:

- **Ed25519 signature verification** - ensures the license file hasn't been tampered with
- **Status and expiry checks** - confirms the license is active and not expired
- **Namespaced license discovery** - multiple licensed packages can coexist in the same application
- **Phone-home validation** - server-side license verification with offline grace periods

Zero external dependencies - uses only the Go standard library.

## For Package Developers

You're building a Go package and want to require a valid RunLicense license before your code runs.

### 1. Add the dependency

```bash
go get github.com/runlicense/sdk-go
```

### 2. Add your public key

Place your RunLicense public key at `keys/runlicense.key` in your module root:

```
your-module/
├── go.mod
├── keys/
│   └── runlicense.key    # Your RunLicense Ed25519 public key (base64)
└── main.go
```

The key is a single line containing the base64-encoded Ed25519 public key. This is the same key shown in your RunLicense dashboard. It gets embedded into your compiled binary at build time via `//go:embed` - it is never read from disk at runtime.

**Important:** Do not add `keys/runlicense.key` to your `.gitignore`. It must be included in your repository so downstream consumers can build your module.

### 3. Verify the license

Choose a namespace for your package. This is typically your organization and package name (e.g., `acme/image-processor`). Your end users will place their license file in a directory matching this namespace.

```go
package main

import (
    "context"
    _ "embed"
    "log"

    runlicense "github.com/runlicense/sdk-go"
)

//go:embed keys/runlicense.key
var publicKey string

func init() {
    license, err := runlicense.Activate(context.Background(), "acme/image-processor", publicKey)
    if err != nil {
        log.Fatalf("License verification failed: %v", err)
    }
    log.Printf("Licensed to: %s", license.CustomerID)
}
```

`Activate` performs the full verification pipeline:

1. Discovers the license file at `runlicense/<namespace>/license.json`
2. Verifies the Ed25519 signature against the embedded public key
3. Checks that the license status is `"active"` and not expired
4. Phones home to the activation server for server-side validation
5. Caches the validation token on disk for offline grace periods

If the network is unavailable, the SDK falls back to a cached validation token if one exists and hasn't expired. If there is no valid cached token, the verification fails.

#### Offline-only verification

If you don't need phone-home validation, use `ActivateOffline`:

```go
license, err := runlicense.ActivateOffline("acme/image-processor", publicKey)
```

> **Security warning:** Without phone-home, the SDK can only verify licenses offline using the signature and expiry date. There is no server-side revocation - if you need to revoke a license, the SDK has no way to know. An end user could also roll back their system clock to bypass expiry checks. Phone-home is the primary enforcement mechanism and should always be enabled in production.

#### With raw JSON

If you load the license JSON yourself (e.g., from a config file or API), use `ActivateFromJSON`:

```go
data, _ := os.ReadFile("/custom/path/license.json")
license, err := runlicense.ActivateFromJSON(context.Background(), string(data), publicKey)
```

This performs the same verification (including phone-home) but without filesystem-based token caching. This means there is no grace period - if phone-home fails, activation fails immediately. Use `ActivateFromJSONOffline` if you need offline-only verification from a JSON string.

#### Feature gating

Use `AllowedFeatures` to gate functionality based on the customer's license tier:

```go
license, err := runlicense.Activate(context.Background(), "acme/image-processor", publicKey)
if err != nil {
    log.Fatal(err)
}

var features map[string]bool
json.Unmarshal(license.AllowedFeatures, &features)

if features["premium-export"] {
    // Enable premium export functionality
}
```

## For Application Developers

You're building a Go application that depends on one or more licensed packages. Each licensed package expects its license file at a specific namespaced path.

### License file placement

Place each license file under a `runlicense/` directory, namespaced by the package's registered namespace:

```
my-application/
├── go.mod
├── runlicense/
│   ├── acme/
│   │   └── image-processor/
│   │       └── license.json
│   └── widgets-inc/
│       └── chart-engine/
│           └── license.json
├── main.go
└── ...
```

Each licensed package finds its own `license.json` independently - they don't interfere with each other.

### Discovery order

The SDK searches for `runlicense/<namespace>/license.json` in these locations, using the first match:

1. **`RUNLICENSE_DIR` environment variable** - if set, looks for `$RUNLICENSE_DIR/<namespace>/license.json`
2. **Executable directory** - next to the compiled binary
3. **Current working directory** - where you run the application from

For deployed applications, it's common to place the `runlicense/` folder alongside the binary or set `RUNLICENSE_DIR` to a fixed path.

### License file format

The `license.json` file is provided by RunLicense when you purchase or activate a license. It contains a signed payload:

```json
{
  "payload": "{\"license_id\":\"lic_abc123\",\"product_id\":\"prod_xyz\",\"customer_id\":\"cust_456\",\"status\":\"active\",\"expiry_date\":\"2027-01-01T00:00:00Z\",\"allowed_features\":{\"pro\":true},\"usage_limit\":null,\"token_ttl\":3600,\"activation_url\":\"https://activate.example.com/v1/validate\"}",
  "signature": "base64-encoded-ed25519-signature"
}
```

You should not modify this file - any changes will cause signature verification to fail.

### Embedding licenses for single-binary distribution

If you need to distribute a single executable without separate license files, you can embed the license into the binary at compile time using `//go:embed` and `SetLicenseJSON`:

```go
package main

import (
    "context"
    _ "embed"
    "log"

    runlicense "github.com/runlicense/sdk-go"
)

//go:embed runlicense/acme/image-processor/license.json
var licenseJSON string

func init() {
    // Register the embedded license before the licensed package initializes.
    // Activate will use this instead of searching the filesystem.
    runlicense.SetLicenseJSON("acme/image-processor", licenseJSON)
}
```

When `SetLicenseJSON` is called for a namespace, `Activate` and `ActivateOffline` use the registered JSON instead of file discovery. The license is still fully verified - signature, status, expiry, and phone-home all apply as normal.

**Important:** Go `init()` functions run in dependency order - your application's `init()` runs after all imported packages' `init()` functions. If a licensed package calls `Activate` in its own `init()`, you need to register the license in a **separate package** that the licensed package imports, or use a different initialization pattern. See the Go specification on [package initialization](https://go.dev/ref/spec#Package_initialization) for details.

## Logging

By default, the SDK operates silently. You can enable verbose logging by passing a `*slog.Logger` via the `WithLogger` option. This is useful during development and testing to see exactly what the SDK is doing at each step of the verification pipeline.

### Enabling logging

```go
import "log/slog"

// Use the default slog logger
result, err := runlicense.Activate(ctx, "acme/image-processor", publicKey,
    runlicense.WithLogger(slog.Default()),
)
```

### Using a custom logger

You can configure any `*slog.Logger` - for example, to set the log level or output format:

```go
// JSON output at debug level
logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

result, err := runlicense.Activate(ctx, "acme/image-processor", publicKey,
    runlicense.WithLogger(logger),
)
```

### Log levels

The SDK uses three log levels:

| Level | What is logged |
|---|---|
| `Debug` | Every verification step: file discovery, signature check, status/expiry validation, phone-home request/response, token verification, cache operations |
| `Info` | Activation start and success (including license ID and customer ID), grace period fallback |
| `Warn` | All failures: file not found, signature mismatch, expired license, phone-home errors, server rejection |

To see all SDK output, set your logger's minimum level to `slog.LevelDebug`. At the default `slog.LevelInfo`, you'll see activation start/success and grace period events.

### Example output

With debug-level logging enabled, a successful activation produces:

```
INFO  [runlicense] starting activation                namespace=acme/image-processor
DEBUG [runlicense] discovering license file            namespace=acme/image-processor
DEBUG [runlicense] license file found                  path=/app/runlicense/acme/image-processor/license.json
DEBUG [runlicense] verifying signature
DEBUG [runlicense] signature verified                  license_id=lic_abc123 customer_id=cust_456
DEBUG [runlicense] checking status and expiry
DEBUG [runlicense] license is active                   status=active expiry_date=2027-01-01T00:00:00Z
DEBUG [runlicense] starting phone-home validation      url=https://activate.example.com/v1/validate
DEBUG [runlicense] generating nonce for phone-home
DEBUG [runlicense] sending phone-home request          url=https://activate.example.com/v1/validate
DEBUG [runlicense] phone-home response received        status=200
DEBUG [runlicense] verifying validation token
DEBUG [runlicense] validation token verified
DEBUG [runlicense] phone-home succeeded                expires_at=2027-01-02T00:00:00Z activations_remaining=5
INFO  [runlicense] activation successful               license_id=lic_abc123 customer_id=cust_456
```

When phone-home fails but a cached token is available:

```
WARN  [runlicense] phone-home failed, checking cached token  error=phone-home validation failed: dial tcp: ...
INFO  [runlicense] using cached validation token (grace period)
```

### Works with all Activate functions

All four activation functions accept `WithLogger`:

```go
runlicense.Activate(ctx, ns, key, runlicense.WithLogger(logger))
runlicense.ActivateOffline(ns, key, runlicense.WithLogger(logger))
runlicense.ActivateFromJSON(ctx, json, key, runlicense.WithLogger(logger))
runlicense.ActivateFromJSONOffline(json, key, runlicense.WithLogger(logger))
```

### For package developers

If you're building a licensed package, you can accept a logger from your consumers and pass it through:

```go
package imageprocessor

import (
    "context"
    _ "embed"
    "log/slog"

    runlicense "github.com/runlicense/sdk-go"
)

//go:embed keys/runlicense.key
var publicKey string

type Option func(*options)
type options struct{ logger *slog.Logger }

func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

func New(ctx context.Context, opts ...Option) (*Client, error) {
    var o options
    for _, fn := range opts { fn(&o) }

    var rlOpts []runlicense.Option
    if o.logger != nil {
        rlOpts = append(rlOpts, runlicense.WithLogger(o.logger))
    }

    result, err := runlicense.Activate(ctx, "acme/image-processor", publicKey, rlOpts...)
    if err != nil {
        return nil, err
    }
    return &Client{license: result}, nil
}
```

This lets the end-user application control logging:

```go
// Application code - opt in to verbose SDK logging
client, err := imageprocessor.New(ctx,
    imageprocessor.WithLogger(slog.Default()),
)
```

## API Reference

### Functions

| Function | Context | Phone-Home | File Discovery | Description |
|---|---|---|---|---|
| `Activate(ctx, namespace, key, ...Option)` | Yes | Yes | Yes | Full verification with server-side validation and grace period |
| `ActivateOffline(namespace, key, ...Option)` | No | No | Yes | Offline-only signature and expiry checks |
| `ActivateFromJSON(ctx, json, key, ...Option)` | Yes | Yes | No | Verify from JSON string, no token caching or grace period |
| `ActivateFromJSONOffline(json, key, ...Option)` | No | No | No | Offline verification from JSON string |
| `SetLicenseJSON(namespace, json)` | - | - | - | Register embedded license; `Activate`/`ActivateOffline` will use it instead of file discovery |

All `Activate*` functions return `(*ActivationResult, error)`. `SetLicenseJSON` has no return value.

### Options

| Option | Description |
|---|---|
| `WithLogger(l *slog.Logger)` | Enable verbose logging using the provided logger. See [Logging](#logging) for details. |

### `LicensePayload`

Returned on successful verification:

| Field | Type | Description |
|---|---|---|
| `LicenseID` | `string` | Unique license identifier |
| `ProductID` | `string` | Product this license is for |
| `CustomerID` | `string` | Customer who owns the license |
| `Status` | `string` | License status (always `"active"` after verification) |
| `ExpiryDate` | `*string` | RFC 3339 expiry date, if set |
| `AllowedFeatures` | `json.RawMessage` | Feature flags/limits as raw JSON, if configured |
| `UsageLimit` | `*uint64` | Usage limit metadata, if configured (informational - not enforced by the SDK) |
| `TokenTTL` | `*uint64` | Validation token TTL in seconds |
| `ActivationURL` | `*string` | Phone-home endpoint URL |

### `LicenseError`

All verification failures return a `*LicenseError` with a `Code` field for programmatic handling:

```go
license, err := runlicense.Activate(context.Background(), "acme/image-processor", publicKey)
if err != nil {
    var licErr *runlicense.LicenseError
    if errors.As(err, &licErr) {
        switch licErr.Code {
        case runlicense.ErrLicenseExpired:
            log.Println("Your license has expired. Please renew.")
        case runlicense.ErrLicenseNotActive:
            log.Println("Your license has been deactivated.")
        case runlicense.ErrSignatureMismatch:
            log.Println("License file is corrupted or tampered with.")
        case runlicense.ErrLicenseFileNotFound:
            log.Println("No license file found. See documentation for setup.")
        default:
            log.Printf("License error: %v", err)
        }
    }
    os.Exit(1)
}
```

### Error Codes

| Code | Description |
|---|---|
| `ErrLicenseFileNotFound` | License file not found in any search path |
| `ErrLicenseFileUnreadable` | License file exists but could not be read |
| `ErrInvalidJSON` | License JSON is malformed |
| `ErrInvalidPublicKey` | The embedded public key is invalid |
| `ErrInvalidSignature` | The signature encoding in the license is invalid |
| `ErrSignatureMismatch` | Signature does not match - license may be tampered |
| `ErrLicenseNotActive` | License status is not `"active"` |
| `ErrLicenseExpired` | License expiry date has passed |
| `ErrNoActivationURL` | No activation URL configured for phone-home |
| `ErrPhoneHomeFailed` | Phone-home request failed (network error, timeout) |
| `ErrInvalidValidationToken` | Server returned an invalid validation token |
| `ErrValidationTokenNonceMismatch` | Token nonce mismatch - possible replay attack |
| `ErrValidationTokenExpired` | Validation token has expired |
| `ErrValidationTokenLicenseMismatch` | Token license ID does not match |
| `ErrServerRejected` | Server explicitly rejected the license |

## Security

- **Ed25519 signatures** ensure license files cannot be forged or modified without the private key
- **Namespace validation** prevents path traversal attacks (`..`, `.`, `\`, empty segments are rejected)
- **Cached tokens are cryptographically verified** on reload - writing a forged `.runlicense_token` file does not bypass validation
- **Phone-home validation** with cryptographic nonce challenges prevents replay attacks
- **Response size limits** prevent denial-of-service via oversized server responses
- **Context support** allows callers to set timeouts and cancel phone-home requests
