package gopocs

import (
	"context"
	"crypto/tls"
	"dddd/internal/common"
	"dddd/internal/structs"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func RabbitMQScan(info *structs.HostInfo) error {
	_, err := RabbitMQUnauth(info)
	return err
}

func RabbitMQUnauth(info *structs.HostInfo) (bool, error) {
	candidates := rabbitMQManagementCandidates(info)
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
	for _, targetURL := range candidates {
		body, statusCode, err := rabbitMQRequest(client, targetURL, "")
		if err != nil {
			lastErr = err
			continue
		}
		if statusCode == http.StatusOK && rabbitMQBodyLooksValid(body) {
			rabbitMQEmit(targetURL, "RabbitMQ管理端未授权访问", "RabbitMQ-Unauth", "HIGH", "未授权", body)
			return true, nil
		}

		body, statusCode, err = rabbitMQRequest(client, targetURL, "guest:guest")
		if err != nil {
			lastErr = err
			continue
		}
		if statusCode == http.StatusOK && rabbitMQBodyLooksValid(body) {
			rabbitMQEmit(targetURL, "RabbitMQ管理端默认口令 guest/guest", "RabbitMQ-WeakAuth", "HIGH", "guest:guest", body)
			return true, nil
		}
	}
	return false, lastErr
}

func rabbitMQManagementCandidates(info *structs.HostInfo) []string {
	type candidate struct {
		scheme string
		port   string
	}

	base := []candidate{{scheme: "http", port: "15672"}, {scheme: "https", port: "15671"}}
	if info.Ports == "15672" {
		base = append([]candidate{{scheme: "http", port: info.Ports}}, base...)
	} else if info.Ports == "15671" {
		base = append([]candidate{{scheme: "https", port: info.Ports}}, base...)
	}

	seen := make(map[string]struct{})
	var urls []string
	for _, item := range base {
		addr := net.JoinHostPort(info.Host, item.port)
		targetURL := fmt.Sprintf("%s://%s/api/overview", item.scheme, addr)
		if _, ok := seen[targetURL]; ok {
			continue
		}
		seen[targetURL] = struct{}{}
		urls = append(urls, targetURL)
	}
	return urls
}

func rabbitMQRequest(client *http.Client, targetURL, basicAuth string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	common.ApplyPocHTTPHeaders(req.Header, "dddd-gopoc")
	if basicAuth != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basicAuth)))
	}

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

func rabbitMQBodyLooksValid(body string) bool {
	lowerBody := strings.ToLower(body)
	return strings.Contains(lowerBody, "rabbitmq_version") || strings.Contains(lowerBody, "management_version") || strings.Contains(lowerBody, "cluster_name")
}

func rabbitMQEmit(targetURL, description, pocName, security, authInfo, body string) {
	showMsg := fmt.Sprintf("RabbitMQ:%s %s", targetURL, authInfo)
	infoLeft := fmt.Sprintf("URL: %s\nAuth: %s\n", targetURL, authInfo)
	emitUnauthGoPoc(pocName, security, targetURL, description, infoLeft, limitInfoRight(body), showMsg)
}
