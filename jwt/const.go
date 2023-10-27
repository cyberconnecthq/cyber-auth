package jwt

import "time"

const (
	cyberPublicKeyUrlProduction = "https://metadata.cyberconnect.dev/auth/public_key_jwk"
	cyberPublicKeyUrlStaging    = "https://metadata.stg.cyberconnect.dev/auth/public_key_jwk"

	cyberCacheAvailableTime = 10 * time.Minute
)

func getCyberPublicKeyUrl(isProduct bool) (url string) {
	if isProduct {
		return cyberPublicKeyUrlProduction
	}
	return cyberPublicKeyUrlStaging
}
