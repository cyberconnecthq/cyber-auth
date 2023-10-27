package jwt

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type cachingClient struct {
	client *http.Client
	mu     sync.Mutex
	certs  map[string]*cachedResponse
}

func newCachingClient(client *http.Client) *cachingClient {
	return &cachingClient{
		client: client,
		certs:  make(map[string]*cachedResponse, 2),
	}
}

type cachedResponse struct {
	resp string
	exp  time.Time
}

func (c *cachingClient) getCert(ctx context.Context, url string) (string, error) {
	if response, ok := c.get(url); ok {
		return response, nil
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"unable to retrieve cert, got status code %d",
			resp.StatusCode,
		)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	c.set(url, string(body), resp.Header)
	return string(body), nil
}

func (c *cachingClient) get(url string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cachedResp, ok := c.certs[url]
	if !ok {
		return "", false
	}
	if time.Now().After(cachedResp.exp) {
		return "", false
	}
	return cachedResp.resp, true
}

func (c *cachingClient) set(url string, resp string, headers http.Header) {
	exp := c.calculateExpireTime()
	c.mu.Lock()
	c.certs[url] = &cachedResponse{resp: resp, exp: exp}
	c.mu.Unlock()
}

func (c *cachingClient) calculateExpireTime() time.Time {
	return time.Now().Add(cyberCacheAvailableTime)
}
