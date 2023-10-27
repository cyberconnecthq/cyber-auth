# CYBER AUTH SDK - GOLANG

## HOW TO USE

Example in jwt/validator_test.go

Cyber claims struct
```
// CyberDappOAuthClaims is used to cyber OAuth
type CyberDappOAuthClaims struct {
	Address string `json:"address,omitempty"`
}
```

Usage

```
cyberValidator, _ := NewCyberValidator(true) // false in stg env (testnet)
testJWT := "your token signed by cyber service"
ctx := context.Background()
payload, err := cyberValidator.ValidateJwtToken(ctx, testJWT)

if err != nil {
    // error handle
    // if invalid jwt token or public key
}

// check user address 
if payload.Address != "your actual address" {
    // biz logic if check address failed
} 

// ...

```