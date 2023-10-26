package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {
	cyberValidator, _ := NewCyberValidator(false)
	testJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlb2EiOiJjeWJlciB0ZXN0IiwiZXhwIjoxNjk4OTgwOTc2LCJpYXQiOjE2OTgzNzYxNzYsImlzcyI6ImN5YmVyLmNvIn0.l9DH7g7Y1IE97CI-NopFXos5MllPeYQt4OlQu4Ar0JU-M0RZvMtSl6NtG4ySb2NFlvrm36mHBU-XDkjQXVZhdw8aC0VOHmyZqdBq-EKiBMDsazQwVhN8ybGtH4TQVDpbAATStRJPNJQmhhrz6dPS-2PVxKi70MrqrfunxsTNpYR8Ke7bHyPrA6LLfAmcZmZ29bV1CRsPLd5sIcPeryrzsC7lahtT55GiEL_0cG4RZq0oWV0Hl_TnIpF8uT0k4c9WAFRAxJq3pchLhFre0H9qufTj8UQRlB6IB_RAxYkUFisotgMMlE6LNyP-cvxVf-GpxuKDNeDkhal389A8tR8GtStKxmHFVX_utMRiCKK1hjNhBFhrDg1gqdMgWFSTY6158tYbhfOTLUoS_EH2vTHD0541YsC2BFOlNJK4tJWx-9zVCAyPUcH5PLPFFCurI2VcHReimzvy9C63H9cUDgA2sjVBsx7CqrZryc1ROIgnihXIIdX6L6k1WvGwfhxWuXUME-qCSJqbtPrn5Gx-_tOzYwiWwma0ZiGHCjb5loNi-q2jmqztU1qFZwMILgiIcBkXuXC-9fXy8App1nDUUBKtV1MGOLTDMsyRLKZQlhaaHJHLcbH3qJ5RmKiwX8Ze_M-WJXZ5q9kjoY5jZfexHcxkCPHB9WIsmlJM6ps1mdtW15A"
	ctx := context.Background()
	payload, err := cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Issuer, "cyber.co")
	assert.True(t, time.Unix(payload.Expires, 0).After(time.Now()))

	// simulate cache
	time.Sleep(5 * time.Second)
	payload, err = cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Issuer, "cyber.co")
	assert.True(t, time.Unix(payload.Expires, 0).After(time.Now()))

	// invalid token
	testJWT = "badtoken" + testJWT
	payload, err = cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.NotNil(t, err)
	assert.Nil(t, payload)
}
