package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {
	cyberValidator, _ := NewCyberValidator(false)
	testJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlb2EiOiJjeWJlciB0ZXN0IiwiZXhwIjoxNjk4OTg3OTg2LCJpYXQiOjE2OTgzODMxODYsImlzcyI6IndhbGxldC5jeWJlci5jbyJ9.wuBGiRUmio67t4ixZpAbDdA55ObeqebxBMMg7i_XDL7n3tW3pc-GxTMyjJPI1chB3qSIiV1RLD5MmURcQqc2sNO6vw1F42Kub2PZZBcy0lC5WIP7c0PajtQouO2mnO2pqXBmrgmu-Sib7S8M50DVgsWPWn-O1l68weVziJQCiB5w0rRrKs1tY7IU_T0oa3YTlap27vsZmpABYAOZwnpRA5LkNjU0wtgDpZadDUhRwcFPmQ0Ib8gMBhdjvK2y65_FaOiygy7p4-VUl9HI6RUe1XEaN6TyVC32Cb1LiWB9u9CQvqjD7FIWhVVSI7ufaI4TOZkR4l7-flnsf_7svo6RFKYd86_ZnPR1QHboeqqhT2fdxRiyKf6EBekTSabhg-jSS-oyxmfjPJ6ABujikygreGSk5o9RRyRqGQ8ybr5B9WAZH6agQePRQg9CSyXK0TR-6Bzp_Mp_61WLak2j0S256-YKXnbfWoOZRpjwYtHXBKA3OVURYqQP5Ti7Ou2k4hBdNo7QF9MGjeLTiDUl3DO7Onskr0xm04k2ddnh_G8DzNExZdphyuYhbwS5GL0hDKM3Irit3ayJA3U_UjqjzH75ehdmliOwNO-yVgVX9x_wjw6Fg3paqmbSOXJGBx7t28y0ypKZfUwMA3feaxboSVBspe7BOC7qNodr8ZeywFrUp0s"
	ctx := context.Background()
	payload, err := cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Issuer, "wallet.cyber.co")
	assert.True(t, time.Unix(payload.Expires, 0).After(time.Now()))

	// simulate cache
	time.Sleep(1 * time.Second)
	payload, err = cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.Nil(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, payload.Issuer, "wallet.cyber.co")
	assert.True(t, time.Unix(payload.Expires, 0).After(time.Now()))

	// invalid token
	testJWT = "badtoken" + testJWT
	payload, err = cyberValidator.ValidateJwtToken(ctx, testJWT)
	assert.NotNil(t, err)
	assert.Nil(t, payload)
}
