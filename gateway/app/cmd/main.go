package main

import (
	"api-getaway/app/internal/config"
	"api-getaway/app/internal/middleware"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/s10n41k/protos/gen/go/sso"
)

const (
	usersURL       = "/users"
	tasksURL       = "/tasks"
	analyticsURL   = "/analytics"
	tasksByUserURL = "/v1/users"

	loginMethod       = "/auth/login"
	registerMethod    = "/auth/register"
	verifyEmailMethod = "/auth/verify-email"
	getAccessToken    = "/auth/get-access-token"
	logoutMethod      = "/auth/logout"
	logoutAllMethod   = "/auth/logout-all"
)

var (
	cfg        *config.Config
	authClient pb.AuthClient
	authConn   *grpc.ClientConn
	authMW     *middleware.AuthMiddleware
	signSecret string
	startTime  = time.Now()
)

func init() {
	// Загружаем конфиг
	cfg = config.Load()

	// Получаем секрет для подписи из переменной окружения
	signSecret = os.Getenv("SIGN_SECRET")
	if signSecret == "" {
		if cfg.SignSecret != "" {
			signSecret = cfg.SignSecret
			log.Println("Using config sign secret (set SIGN_SECRET env variable for production)")
		} else {
			log.Fatal("SIGN_SECRET environment variable is required")
		}
	}

	// Инициализируем middleware аутентификации
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		slog.Error("jwt secret is empty")
		log.Printf("WARNING: Using default JWT secret. Set JWT_SECRET env variable in production!")
	}
	authMW = middleware.NewAuthMiddleware(jwtSecret)

	// Инициализируем gRPC клиент
	initGRPCClient()
}

func main() {
	// Настройка Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Глобальные middleware
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())
	r.Use(loggingMiddleware())

	// Public routes (не требуют аутентификации)
	r.POST(loginMethod, handleAuthRequest(loginHandler))
	r.POST(registerMethod, handleAuthRequest(registerHandler))
	r.POST(verifyEmailMethod, handleAuthRequest(verifyEmailHandler))
	r.POST(getAccessToken, handleAuthRequest(refreshTokenHandler))

	r.GET("/health", healthHandler)
	r.GET("/metrics", metricsHandler)

	// Protected routes (требуют аутентификации)
	protected := r.Group("/")
	protected.Use(authMW.Handler())
	{
		// Auth service routes (через gRPC)
		protected.POST(logoutMethod, handleAuthRequest(logoutHandler))
		protected.POST(logoutAllMethod, handleAuthRequest(logoutAllHandler))

		// User info endpoint
		protected.GET("/me", userInfoHandler)

		// Service proxies
		protected.Any(usersURL+"/*path", createSignedProxy(cfg.Services.Users.Host, cfg.Services.Users.Port))
		protected.Any(tasksURL+"/*path", createSignedProxy(cfg.Services.Tasks.Host, cfg.Services.Tasks.Port))
		protected.Any(analyticsURL+"/*path", createSignedProxy(cfg.Services.Analytics.Host, cfg.Services.Analytics.Port))
		protected.Any(tasksByUserURL+"/*path", createSignedProxy(cfg.Services.Tasks.Host, cfg.Services.Tasks.Port))
	}

	// Настройка HTTP сервера
	server := &http.Server{
		Addr:         cfg.Listen.BindIP + ":" + cfg.Listen.Port,
		Handler:      r,
		ReadTimeout:  cfg.Listen.Timeout,
		WriteTimeout: cfg.Listen.Timeout,
		IdleTimeout:  60 * time.Second,
	}

	// Канал для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Запуск сервера в отдельной горутине
	go func() {
		log.Printf("Gateway started on http://%s:%s", cfg.Listen.BindIP, cfg.Listen.Port)
		log.Printf("Using sign secret: %s...", signSecret[:min(4, len(signSecret))])
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start gateway:", err)
		}
	}()

	// Ожидание сигнала shutdown
	<-quit
	log.Println("Shutting down gateway...")

	// Graceful shutdown с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Останавливаем HTTP сервер
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Gateway forced to shutdown:", err)
	}

	// Закрываем gRPC соединение
	if authConn != nil {
		authConn.Close()
		log.Println("gRPC connection closed")
	}

	log.Println("Gateway shutdown complete")
}

// ===== Функции для работы с подписью =====

// createSignature создает HMAC-SHA256 подпись для данных
func createSignature(data string) string {
	h := hmac.New(sha256.New, []byte(signSecret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// signRequest добавляет подпись к запросу
func signRequest(req *http.Request, userData map[string]string) {
	// Собираем данные для подписи
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	var parts []string
	parts = append(parts, req.Method)
	parts = append(parts, req.URL.Path)
	parts = append(parts, timestamp)

	// Добавляем пользовательские данные
	if userID, ok := userData["user_id"]; ok {
		parts = append(parts, userID)
	}
	if session, ok := userData["session"]; ok {
		parts = append(parts, session)
	}

	// Создаем подпись
	dataToSign := strings.Join(parts, "|")
	signature := createSignature(dataToSign)

	// Добавляем заголовки
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature-Version", "1")
}

// ===== Обработчики auth (HTTP → gRPC) =====

type authHandlerFunc func(*gin.Context, *pb.AuthClient) error

func handleAuthRequest(handler authHandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), cfg.Services.Auth.Timeout)
		defer cancel()

		// Создаем новый контекст для gRPC вызова
		grpcCtx := c.Request.WithContext(ctx)
		c.Request = grpcCtx

		if err := handler(c, &authClient); err != nil {
			log.Printf("Auth request failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
	}
}

func loginHandler(c *gin.Context, client *pb.AuthClient) error {
	var req pb.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return nil
	}

	resp, err := (*client).Login(c.Request.Context(), &req)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	c.JSON(http.StatusOK, resp)
	return nil
}

func registerHandler(c *gin.Context, client *pb.AuthClient) error {
	var req pb.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return nil
	}

	resp, err := (*client).Register(c.Request.Context(), &req)
	if err != nil {
		return fmt.Errorf("register failed: %w", err)
	}

	c.JSON(http.StatusCreated, resp)
	return nil
}

func verifyEmailHandler(c *gin.Context, client *pb.AuthClient) error {
	var req pb.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return nil
	}

	resp, err := (*client).VerifyEmail(c.Request.Context(), &req)
	if err != nil {
		return fmt.Errorf("email verification failed: %w", err)
	}

	c.JSON(http.StatusOK, resp)
	return nil
}

func refreshTokenHandler(c *gin.Context, client *pb.AuthClient) error {
	var req pb.TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return nil
	}

	resp, err := (*client).GetAccessToken(c.Request.Context(), &req)
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}

	c.JSON(http.StatusOK, resp)
	return nil
}

func logoutHandler(c *gin.Context, client *pb.AuthClient) error {
	var req pb.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return nil
	}

	resp, err := (*client).Logout(c.Request.Context(), &req)
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	c.JSON(http.StatusOK, resp)
	return nil
}

func logoutAllHandler(c *gin.Context, client *pb.AuthClient) error {
	var req pb.LogoutAllRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return nil
	}

	resp, err := (*client).LogoutAll(c.Request.Context(), &req)
	if err != nil {
		return fmt.Errorf("logout all failed: %w", err)
	}

	c.JSON(http.StatusOK, resp)
	return nil
}

// ===== Обработчики HTTP endpoints =====

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   "gateway",
		"uptime":    time.Since(startTime).Seconds(),
	})
}

func metricsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"uptime":  time.Since(startTime).Seconds(),
		"status":  "ok",
		"version": "1.0.0",
	})
}

func userInfoHandler(c *gin.Context) {
	userInfo := gin.H{
		"user_id": c.GetString("user_id"),
		"roles":   c.GetString("roles"),
		"session": c.GetString("session"),
		"jti":     c.GetString("jti"),
		"version": c.GetInt("token_version"),
	}

	c.JSON(http.StatusOK, userInfo)
}

// ===== HTTP прокси =====

func createSignedProxy(host, port string) gin.HandlerFunc {
	return func(c *gin.Context) {
		targetURL := fmt.Sprintf("http://%s:%s", host, port)

		url, err := url.Parse(targetURL)
		if err != nil {
			log.Printf("Failed to parse target URL %s: %v", targetURL, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(url)
		origDirector := proxy.Director

		proxy.Director = func(req *http.Request) {
			origDirector(req)

			// Убираем префикс маршрута
			req.URL.Path = stripRoutePrefix(req.URL.Path)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}

			// Сохраняем оригинальный Authorization
			if authHeader := req.Header.Get("Authorization"); authHeader != "" {
				req.Header.Set("X-Original-Authorization", authHeader)
				req.Header.Del("Authorization")
			}

			// Собираем данные пользователя для подписи
			userData := make(map[string]string)

			if userID, exists := c.Get("user_id"); exists {
				userIDStr := fmt.Sprintf("%v", userID)
				req.Header.Set("X-User-ID", userIDStr)
				userData["user_id"] = userIDStr
			}
			if roles, exists := c.Get("roles"); exists {
				req.Header.Set("X-User-Roles", fmt.Sprintf("%v", roles))
			}
			if session, exists := c.Get("session"); exists {
				sessionStr := fmt.Sprintf("%v", session)
				req.Header.Set("X-Session-ID", sessionStr)
				userData["session"] = sessionStr
			}
			if tokenVersion, exists := c.Get("token_version"); exists {
				req.Header.Set("X-Token-Version", fmt.Sprintf("%d", tokenVersion))
			}
			if jti, exists := c.Get("jti"); exists {
				req.Header.Set("X-JTI", fmt.Sprintf("%v", jti))
			}

			// Добавляем подпись запроса
			signRequest(req, userData)

			// Дополнительные заголовки
			req.Header.Set("X-Forwarded-By", "gateway")
			req.Header.Set("X-Forwarded-For", getClientIP(req))
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-Proto", "http")
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			}

			// Добавляем имя сервиса, от которого идет запрос
			req.Header.Set("X-Service-Name", "gateway")
		}

		// Обслуживаем запрос через прокси
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func stripRoutePrefix(path string) string {
	prefixes := []string{usersURL, tasksURL, analyticsURL, tasksByUserURL}
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix)
		}
	}
	return path
}

func getClientIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	return req.RemoteAddr
}

// ===== Инициализация gRPC =====

func initGRPCClient() {
	var err error
	authConn, err = grpc.NewClient(
		cfg.Services.Auth.Host+":"+cfg.Services.Auth.Port,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithTimeout(cfg.Services.Auth.Timeout),
	)
	if err != nil {
		log.Fatal("Failed to connect to auth service:", err)
	}
	authClient = pb.NewAuthClient(authConn)
	log.Println("Connected to auth service")
}

// ===== Middleware =====

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Accept, Origin, Cache-Control, X-Requested-With, X-Signature, X-Timestamp, X-Service-Name")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)
		userID := c.GetString("user_id")

		log.Printf("[GATEWAY] %s %s %d %v %s",
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			duration,
			userID,
		)
	}
}

// ===== Вспомогательные функции =====

func minimum(a, b int) int {
	if a < b {
		return a
	}
	return b
}
