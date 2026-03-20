package config

import (
	"os"
	"strings"
)

type Config struct {
	GatewayURL string
	IntelURL   string
	RedisAddr  string
}

func Load() Config {
	return Config{
		GatewayURL: normalizeURL(envOrDefault("SPECTRE_GATEWAY_URL", "http://127.0.0.1:8080")),
		IntelURL:   normalizeURL(envOrDefault("SPECTRE_INTEL_URL", "http://127.0.0.1:5004")),
		RedisAddr:  envOrDefault("REDIS_ADDR", "127.0.0.1:6379"),
	}
}

func (c Config) RootURL() string {
	return c.GatewayURL + "/"
}

func (c Config) DashboardURL(sessionID string) string {
	return c.GatewayURL + "/dashboard?session=" + sessionID
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func normalizeURL(raw string) string {
	return strings.TrimRight(raw, "/")
}
