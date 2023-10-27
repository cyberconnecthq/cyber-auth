# CYBER AUTH SDK - GOLANG

## HOW TO USE

Example in jwt/validator_test.go

Usage

```
cyberValidator, _ := NewCyberValidator(false) // true is production env
testJWT := "token signed by cyber service"
ctx := context.Background()
payload, err := cyberValidator.ValidateJwtToken(ctx, testJWT)

if err != nil {
    // if invalid jwt token or public key
}

if payload.Issuer != "wallet.cyber.co" {
    // not signed by cyber
}

if time.Unix(payload.Expires, 0).Before(time.Now()) {
    // token is expired
} 

// 
```