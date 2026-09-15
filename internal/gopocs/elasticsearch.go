package gopocs

import (
	"context"
	"crypto/tls"
	"dddd/internal/common"
	"dddd/internal/structs"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func ElasticsearchScan(info *structs.HostInfo) error {
	_, err := ElasticsearchUnauth(info)
	return err
}

func ElasticsearchUnauth(info *structs.HostInfo) (bool, error) {
	addr := net.JoinHostPort(info.Host, info.Ports)
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}

	var lastErr error
	for _, scheme := range []string{"http", "https"} {
		targetURL := fmt.Sprintf("%s://%s/", scheme, addr)
		body, statusCode, err := elasticsearchRequest(client, targetURL)
		if err != nil {
			lastErr = err
			continue
		}

		lowerBody := strings.ToLower(body)
		if statusCode == http.StatusOK && strings.Contains(lowerBody, "cluster_name") && strings.Contains(lowerBody, "\"version\"") {
			showMsg := fmt.Sprintf("Elasticsearch:%s Unauthorized", targetURL)
			infoLeft := fmt.Sprintf("URL: %s\nStatus: %d\n", targetURL, statusCode)
			emitUnauthGoPoc("Elasticsearch-Unauth", "HIGH", targetURL, "Elasticsearch未授权访问", infoLeft, limitInfoRight(body), showMsg)
			return true, nil
		}

		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			return false, nil
		}
	}
	return false, lastErr
}

func elasticsearchRequest(client *http.Client, targetURL string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	common.ApplyPocHTTPHeaders(req.Header, "dddd-gopoc")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(bodyBytes), resp.StatusCode, nil
}
