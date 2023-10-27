package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

// CyberDappOAuthClaims is used to cyber OAuth
type CyberDappOAuthClaims struct {
	Address string `json:"address,omitempty"`
	jwt.StandardClaims
}

type CyberValidator struct {
	publicKey     *rsa.PublicKey
	cachingClient *cachingClient
	isProduct     bool
}

// NewCyberValidator
// pass your env to select cyber auth env
// true -> online, production
// false -> testnet, staging
func NewCyberValidator(isProduct bool) *CyberValidator {
	return &CyberValidator{
		cachingClient: newCachingClient(&http.Client{}),
		isProduct:     isProduct,
	}
}

// ValidateJwtToken
// return userAddress in jwt token
func (v *CyberValidator) ValidateJwtToken(ctx context.Context, token string) (*CyberDappOAuthClaims, error) {
	rawKey, err := v.cachingClient.getCert(ctx, getCyberPublicKeyUrl(v.isProduct))
	if err != nil {
		return nil, err
	}
	if len(rawKey) == 0 {
		return nil, errors.New("invalid cache len")
	}
	key, err := jwk.ParseKey([]byte(rawKey))
	var publicKey interface{}
	err = key.Raw(&publicKey)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parse jwk to rsa public key failed")
	}
	// parse token to cyber claims
	parsedToken, err := jwt.ParseWithClaims(token, &CyberDappOAuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	// convert to cyber claims
	cyberDappOAuthClaims, ok := parsedToken.Claims.(*CyberDappOAuthClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return cyberDappOAuthClaims, nil
}
