# RunLicense Go SDK - Quickstart

## Part 1: Create a Licensed Package

### 1. Create the package module

```bash
mkdir my-package && cd my-package
go mod init github.com/yourorg/my-package
```

### 2. Add the SDK dependency

```bash
go get github.com/runlicense/sdk-go
```

### 3. Add your public key

```bash
mkdir -p keys
```

Copy your Ed25519 public key (from the RunLicense dashboard) into `keys/runlicense.key`:

```bash
echo "YOUR_BASE64_PUBLIC_KEY" > keys/runlicense.key
```

### 4. Add license verification

Create your package entry point (e.g. `mypackage.go`):

```go
package mypackage

import (
    "context"
    _ "embed"
    "fmt"

    runlicense "github.com/runlicense/sdk-go"
)

//go:embed keys/runlicense.key
var publicKey string

func New(ctx context.Context) (*Client, error) {
    result, err := runlicense.Activate(ctx, "yourorg/my-package", publicKey)
    if err != nil {
        return nil, fmt.Errorf("license verification failed: %w", err)
    }
    return &Client{license: result}, nil
}

type Client struct {
    license *runlicense.ActivationResult
}

func (c *Client) Hello() string {
    return "licensed and working"
}
```

### 5. Publish

```bash
git init && git add -A && git commit -m "initial release"
git tag v0.1.0
git push origin main --tags
```

---

## Part 2: Create an App Using the Licensed Package

_The developer using your licensed package would perform these steps_

### 1. Create the app module

```bash
mkdir my-app && cd my-app
go mod init github.com/yourorg/my-app
```

### 2. Add the licensed package

```bash
go get github.com/yourorg/my-package
```

### 3. Create a license

1. Go to the RunLicense dashboard
2. Navigate to **Licenses > New License**
3. Select your product and customer, then click **Create License**
4. On the license page, copy the license JSON

### 4. Place the license file

```bash
mkdir -p runlicense/yourorg/my-package
```

Paste the copied license JSON into the namespace directory:

```bash
cat > runlicense/yourorg/my-package/license.json << 'EOF'
{
  "payload": "...",
  "signature": "..."
}
EOF
```

### 5. Use the package

Create `main.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"

    mypackage "github.com/yourorg/my-package"
)

func main() {
    client, err := mypackage.New(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(client.Hello())
}
```

### 6. Run

```bash
go run .
```

The SDK discovers the license at `runlicense/yourorg/my-package/license.json`, verifies the signature, checks status/expiry, and phones home for server-side validation.

---

## Directory Structures

**Package:**

```
my-package/
├── go.mod
├── keys/
│   └── runlicense.key
└── mypackage.go
```

**App:**

```
my-app/
├── go.mod
├── main.go
└── runlicense/
    └── yourorg/
        └── my-package/
            └── license.json
```

---

## License Discovery Order

The SDK searches for `runlicense/<namespace>/license.json` in:

1. `$RUNLICENSE_DIR/<namespace>/license.json` (if env var is set)
2. Next to the compiled binary
3. Current working directory
