package config

import (
	"os"
	"time"
)

type Config struct {
	Services ServicesConfig
	Listen   Listen
}

type Listen struct {
	Type    string        `yaml:"type" env-default:"port"`
	Port    string        `yaml:"port" env-default:"3000"`
	BindIP  string        `yaml:"bind_ip" env-default:"0.0.0.0"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

type ServiceConfig struct {
	Host    string
	Port    string
	Timeout time.Duration
}

type ServicesConfig struct {
	Auth      ServiceConfig
	Users     ServiceConfig
	Tasks     ServiceConfig
	Analytics ServiceConfig
}

func Load() *Config {
	return &Config{
		Services: ServicesConfig{
			Auth: ServiceConfig{
				Port:    getEnv("AUTH_SERVICE_PORT", "8787"),
				Host:    getEnv("AUTH_SERVICE_HOST", "auth-service"),
				Timeout: parseDuration(getEnv("AUTH_SERVICE_TIMEOUT", "5s")),
			},
			Users: ServiceConfig{
				Host:    getEnv("USERS_SERVICE_HOST", "users-service"),
				Port:    getEnv("USERS_SERVICE_PORT", "8080"),
				Timeout: parseDuration(getEnv("USERS_SERVICE_TIMEOUT", "5s")),
			},
			Tasks: ServiceConfig{
				Host:    getEnv("TASKS_SERVICE_HOST", "tasks-service"),
				Port:    getEnv("TASKS_SERVICE_PORT", "8000"),
				Timeout: parseDuration(getEnv("TASKS_SERVICE_TIMEOUT", "10s")),
			},
			Analytics: ServiceConfig{
				Host:    getEnv("ANALYTICS_SERVICE_HOST", "analytics-service"),
				Port:    getEnv("ANALYTICS_SERVICE_PORT", "5050"),
				Timeout: parseDuration(getEnv("ANALYTICS_SERVICE_TIMEOUT", "8s")),
			},
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Second
	}
	return d
}
