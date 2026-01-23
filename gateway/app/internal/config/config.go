package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Listen struct {
		BindIP  string
		Port    string
		Timeout time.Duration
	}
	Services struct {
		Auth struct {
			Host    string
			Port    string
			Timeout time.Duration
		}
		Users struct {
			Host string
			Port string
		}
		Tasks struct {
			Host string
			Port string
		}
		Analytics struct {
			Host string
			Port string
		}
	}
	SignSecret string
}

func Load() *Config {
	cfg := &Config{}

	// Listen config
	cfg.Listen.BindIP = getEnv("GATEWAY_BIND_IP", "localhost")
	cfg.Listen.Port = getEnv("GATEWAY_PORT", "8080")
	cfg.Listen.Timeout = getDurationEnv("GATEWAY_TIMEOUT", 5*time.Second)

	// Services config
	cfg.Services.Auth.Host = getEnv("AUTH_SERVICE_HOST", "localhost")
	cfg.Services.Auth.Port = getEnv("AUTH_SERVICE_PORT", "50051")
	cfg.Services.Auth.Timeout = getDurationEnv("AUTH_SERVICE_TIMEOUT", 10*time.Second)

	cfg.Services.Users.Host = getEnv("USERS_SERVICE_HOST", "localhost")
	cfg.Services.Users.Port = getEnv("USERS_SERVICE_PORT", "8081")

	cfg.Services.Tasks.Host = getEnv("TASKS_SERVICE_HOST", "localhost")
	cfg.Services.Tasks.Port = getEnv("TASKS_SERVICE_PORT", "8082")

	cfg.Services.Analytics.Host = getEnv("ANALYTICS_SERVICE_HOST", "localhost")
	cfg.Services.Analytics.Port = getEnv("ANALYTICS_SERVICE_PORT", "8083")

	// Signature secret
	cfg.SignSecret = getEnv("SIGN_SECRET", "")

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if dur, err := time.ParseDuration(value); err == nil {
			return dur
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
