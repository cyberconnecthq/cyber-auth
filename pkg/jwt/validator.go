package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

// Payload represents a decoded payload of an ID Token.
type Payload struct {
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	Expires  int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	Subject  string                 `json:"sub,omitempty"`
	Claims   map[string]interface{} `json:"-"`
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
func NewCyberValidator(isProduct bool) (*CyberValidator, error) {
	return &CyberValidator{
		cachingClient: newCachingClient(&http.Client{}),
		isProduct:     isProduct,
	}, nil
}

// ValidateJwtToken
// return userAddress in jwt token
func (v *CyberValidator) ValidateJwtToken(ctx context.Context, token string) (*Payload, error) {
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
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	// marshal a map
	rawClaimBytes, err := json.Marshal(parsedToken.Claims)
	if err != nil {
		return nil, err
	}

	payload := &Payload{}
	if err := json.Unmarshal(rawClaimBytes, &payload); err != nil {
		return nil, fmt.Errorf("idtoken: unable to unmarshal JWT payload: %v", err)
	}
	if err := json.Unmarshal(rawClaimBytes, &payload.Claims); err != nil {
		return nil, fmt.Errorf("idtoken: unable to unmarshal JWT payload claims: %v", err)
	}

	return payload, nil
}
