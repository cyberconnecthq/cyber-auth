package jwt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {
	// test stg
	cyberValidator := NewCyberValidator(false)
	testJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjoiY3liZXIgdGVzdCIsImV4cCI6MjAxNDAwODEzOCwiaWF0IjoxNjk4Mzg4OTM4LCJpc3MiOiJ3YWxsZXQuY3liZXIuY28ifQ.NxlarWPmVOG9OepZvBxBwCZ2jYGF-c0QIicfxSKhPKy9xq2NeE8rlm031THqQMevlwWFMXbMOrTatfEoq-wMrEFVA__30fuWPd8SHq7NTTFZMZCIdDFvXAo96U6Ft4-fARC7fi3-39a1Q75uSmBAnl0ARJzKeSsJwvEnq9p6mFmgB8lQCTzLFz6z_glSrYMUjIBGTzJpx-PQMG3NmzPFAiQt6POmgBBgQgHXcxRtDRjz4XvfB8Y2kQjs-hT6x-IuQNchRGcaS-wa4IEEdcz8rRs6erp-GV0AtQ10z_V5Wb_B-RkMOPuW2E3nXHKIw1XE_bsRhGPM4zRXr5VS6gUDOw"
	ctx := context.Background()
	// check first time with no cache latency
	//start := time.Now()
	payload, err := cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Address, "cyber test")
	//fmt.Println(time.Now().Sub(start).Seconds())

	// check second time query hit cache latency
	//start = time.Now()
	payload, err = cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Address, "cyber test")
	//fmt.Println(time.Now().Sub(start).Seconds())

	// invalid token
	testJWT = "badtoken" + testJWT
	// check invalid token verify time cost
	//start = time.Now()
	payload, err = cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.NotNil(t, err)
	assert.Nil(t, payload)
	//fmt.Println(time.Now().Sub(start).Seconds())

	// test prd
	cyberValidatorPrd := NewCyberValidator(true)
	//start = time.Now()
	testJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjoiY3liZXIgdGVzdCIsImV4cCI6MjAxNDAwODE2NiwiaWF0IjoxNjk4Mzg4OTY2LCJpc3MiOiJ3YWxsZXQuY3liZXIuY28ifQ.q1LHrAhFUnhoYN5TflDG_iYxVHf2-E2YF4InPkVrWtiHhXJQA-9vhuRlacbt5wGZdnLcrbQkpHmHCC1uajcscAfBKP5p5msL6C-fGze_euoYgVj7VrFJ0btkNb6HNI7cAfMngtcpsKfjidVgz8XiYmL01FX727pVKpR5nC3TwFZlpq16NQ6oUFIUAsMyHjlTqc03QP12UQ7lX31PWkkqPeqBkDNI80mTMStMm9TKy_qb7Nlm4etINuYm5zRz_gtJPgrt1d5oBiG87ICjFsINhC-lcw2dp6XsjXOAd4UcUabQYgS7U0RnJMvFfbgVzdCdr7DJ1_RLFvmDladB7mLqGQ"
	ctx = context.Background()
	payload, err = cyberValidatorPrd.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Address, "cyber test")
	//fmt.Println(time.Now().Sub(start).Seconds())

	//start = time.Now()
	payload, err = cyberValidatorPrd.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Address, "cyber test")
	//fmt.Println(time.Now().Sub(start).Seconds())

	// invalid token
	//start = time.Now()
	testJWT = "badtoken" + testJWT
	payload, err = cyberValidatorPrd.ValidateJwtToken(ctx, testJWT)
	assert.NotNil(t, err)
	assert.Nil(t, payload)
	//fmt.Println(time.Now().Sub(start).Seconds())
}
