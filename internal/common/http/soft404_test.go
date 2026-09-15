package http

import (
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

func TestIsActivePathEchoError(t *testing.T) {
	tests := []struct {
		name string
		resp runner.Result
		want bool
	}{
		{
			name: "json error echoes active path with 500",
			resp: runner.Result{
				Path:        "/swagger-ui/index.html",
				StatusCode:  500,
				ContentType: "application/json",
				Body:        `{"timestamp":"2026-05-30T00:00:00Z","status":500,"error":"Internal Server Error","path":"/swagger-ui/index.html"}`,
			},
			want: true,
		},
		{
			name: "json error with 200 echoes active path",
			resp: runner.Result{
				Path:        "/actuator",
				StatusCode:  200,
				ContentType: "application/json; charset=utf-8",
				Body:        `{"code":404,"message":"not found","path":"/actuator"}`,
			},
			want: true,
		},
		{
			name: "express style error echoes active path",
			resp: runner.Result{
				Path:        "/druid/login.html",
				StatusCode:  404,
				ContentType: "text/html; charset=utf-8",
				Body:        `Cannot GET /druid/login.html`,
			},
			want: true,
		},
		{
			name: "actuator index is valid json content",
			resp: runner.Result{
				Path:        "/actuator",
				StatusCode:  200,
				ContentType: "application/json",
				Body:        `{"_links":{"self":{"href":"http://127.0.0.1/actuator"},"health":{"href":"http://127.0.0.1/actuator/health"}}}`,
			},
			want: false,
		},
		{
			name: "swagger ui html page has strong title evidence",
			resp: runner.Result{
				Path:        "/swagger-ui/index.html",
				StatusCode:  200,
				ContentType: "text/html; charset=utf-8",
				Title:       "Swagger UI",
				Body:        `<html><title>Swagger UI</title><script src="/swagger-ui/swagger-ui-bundle.js"></script></html>`,
			},
			want: false,
		},
		{
			name: "body mentions path without error shape",
			resp: runner.Result{
				Path:        "/kibana",
				StatusCode:  200,
				ContentType: "application/json",
				Body:        `{"name":"kibana","basePath":"/kibana","version":"8.0.0"}`,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isActivePathEchoError(tt.resp); got != tt.want {
				t.Fatalf("isActivePathEchoError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsActiveFingerConfirmable(t *testing.T) {
	tests := []struct {
		name string
		resp runner.Result
		want bool
	}{
		{
			name: "plain not found page without web markers",
			resp: runner.Result{
				Path:        "/smartbi/vision/index.jsp",
				StatusCode:  404,
				ContentType: "text/html",
				Body:        "Not Found\nThe requested URL /smartbi/vision/index.jsp was not found on this server.",
			},
			want: false,
		},
		{
			name: "swagger ui html page has script tag",
			resp: runner.Result{
				Path:        "/swagger-ui/index.html",
				StatusCode:  200,
				ContentType: "text/html; charset=utf-8",
				Title:       "Swagger UI",
				Body:        `<html><title>Swagger UI</title><script src="/swagger-ui/swagger-ui-bundle.js"></script></html>`,
			},
			want: true,
		},
		{
			name: "nacos login page has form and class",
			resp: runner.Result{
				Path:        "/nacos/",
				StatusCode:  200,
				ContentType: "text/html",
				Body:        `<div class="login"><form action="/nacos/v1/auth/login"><input name="username"/></form></div>`,
			},
			want: true,
		},
		{
			name: "json error without page markers is not confirmable",
			resp: runner.Result{
				Path:        "/actuator",
				StatusCode:  200,
				ContentType: "application/json",
				Body:        `{"code":404,"message":"not found","path":"/actuator"}`,
			},
			want: false,
		},
		{
			name: "valid api docs json has link-like structure",
			resp: runner.Result{
				Path:        "/v2/api-docs",
				StatusCode:  200,
				ContentType: "application/json",
				Body:        `{"swagger":"2.0","info":{"title":"API"},"paths":{"/users":{"get":{"summary":"list"}}}}`,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isActiveFingerConfirmable(tt.resp); got != tt.want {
				t.Fatalf("isActiveFingerConfirmable() = %v, want %v", got, tt.want)
			}
		})
	}
}
