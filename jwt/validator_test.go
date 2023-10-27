package jwt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {
	// test stg
	cyberValidator := NewCyberValidator(false)
	testJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjoiY3liZXIgdGVzdCIsImV4cCI6MTY5ODk5Mjc1NSwiaWF0IjoxNjk4Mzg3OTU1LCJpc3MiOiJ3YWxsZXQuY3liZXIuY28ifQ.M4XzXXcw7ch6xXIHDHAV7qHQVKgdPNpyQjBrwOT3sBdkIlnAuKfrjig6lx_nUHJdT8rZCy_AxuDHFD25_HARIYas4-r1uBsQWFHoSP705GD1svawuQrksoLkgyUmgIhJvfZJ4ckB7yeI0PqBDpyJm9nowOGGqYVo4kHUq_D2FImXHfWlu5eW6aBr9hv09UW4pAB2bHy1vjdoGhR5T1LQuhzk-82IzU0ryDqBfaCjvU7PLd3EWtdo5N5EFeOBUzP5eVU56X_39lY-INv-klOXOTQ7f2FrZBO2zpuL9lpY0Uo_SM6IHQOF8CmuTKeGp17gkkdloKUaNzZfB9BpHiHWrA"
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
	testJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjoiY3liZXIgdGVzdCIsImV4cCI6MTY5ODk5MjczNywiaWF0IjoxNjk4Mzg3OTM3LCJpc3MiOiJ3YWxsZXQuY3liZXIuY28ifQ.eRpoTsL91OgHCgFJADpNARuDk0qZihMgQU_e2aMhcu4Tr_Osq49bYFvhIs1il-JKvQrAHrhU2-QTriZP7_hQa3yl1KOh2a4HtB6atqfCtH7Px9u3oE0cfyN6Ul8BCOIHttIH1Yjnmdq66kpN302qzNhmvqUJ3lsikfzBMQC97ceUtkoieqfAERvvfdX8NvNTRE0GED0lp0N3P_y1TFlXV3fnqHFuHOzBJkyxm9h-LzgB6ACygAIEkcFqoqgUqJt_PIqvGUfQ7DOS7WpWdcoGei5qtTJ32mympGjcQBz9xZiTTnEmmoeiZxUyMqJFzJOIXVWF9Rj6BRZmDEu5pk7cew"
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
