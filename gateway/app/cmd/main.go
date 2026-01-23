package main

import (
	"api-getaway/app/internal/config"
	"api-getaway/app/internal/middleware"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
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

	// Секрет для подписи внутренних запросов
	internalSecret = "gateway-internal-secret-key-change-me"
)

var (
	authClient     pb.AuthClient
	authConn       *grpc.ClientConn
	authMiddleware *middleware.AuthMiddleware
)

func init() {
	// Инициализируем middleware с секретом из конфигурации или переменных окружения
	// В production используй переменные окружения!
	secret := getJWTSecret()
	authMiddleware = middleware.NewAuthMiddleware(secret)

	// Устанавливаем обработчик graceful shutdown
	// Можно добавить signal.Notify для обработки SIGTERM, SIGINT
}

func main() {
	cfg := config.Load()
	r := gin.Default()

	// Инициализация gRPC клиента для auth-service
	initAuthClient(cfg)

	// Глобальные middleware
	r.Use(corsMiddleware())
	r.Use(loggerMiddleware())

	// Public routes (не требуют аутентификации)
	public := r.Group("/")
	{
		public.POST(loginMethod, func(c *gin.Context) { callAuthService(c, cfg, "login") })
		public.POST(registerMethod, func(c *gin.Context) { callAuthService(c, cfg, "register") })
		public.POST(verifyEmailMethod, func(c *gin.Context) { callAuthService(c, cfg, "verify_email") })
		public.POST(getAccessToken, func(c *gin.Context) { callAuthService(c, cfg, "get_access_token") })

		public.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "gateway ok", "timestamp": time.Now().Unix()})
		})

		// Метрики и документация
		public.GET("/metrics", metricsHandler)
		public.GET("/docs/*any", docsHandler)
	}

	// Protected routes (требуют аутентификации)
	protected := r.Group("/")
	protected.Use(authMiddleware.Handler())
	{
		// Auth routes (требуют токен)
		protected.POST(logoutMethod, func(c *gin.Context) { callAuthService(c, cfg, "logout") })
		protected.POST(logoutAllMethod, func(c *gin.Context) { callAuthService(c, cfg, "logout_all") })

		// Service proxies с подписанными запросами
		protected.Any(usersURL+"/*path", createSignedProxy(buildTarget(cfg.Services.Users.Host, cfg.Services.Users.Port)))
		protected.Any(tasksURL+"/*path", createSignedProxy(buildTarget(cfg.Services.Tasks.Host, cfg.Services.Tasks.Port)))
		protected.Any(tasksByUserURL+"/*path", createSignedProxy(buildTarget(cfg.Services.Tasks.Host, cfg.Services.Tasks.Port)))
		protected.Any(analyticsURL+"/*path", createSignedProxy(buildTarget(cfg.Services.Analytics.Host, cfg.Services.Analytics.Port)))

		// User info endpoint
		protected.GET("/me", getUserInfoHandler)
	}

	log.Println("Gateway started on " + cfg.Listen.BindIP + ":" + cfg.Listen.Port)
	if err := r.Run(cfg.Listen.BindIP + ":" + cfg.Listen.Port); err != nil {
		log.Fatal("Failed to start gateway:", err)
	}
}

// ===== Вспомогательные функции =====

func getJWTSecret() string {
	// В production используй переменные окружения!
	// Пример: os.Getenv("JWT_SECRET")
	secret := "your-super-secret-jwt-key-change-in-production"
	if secret == "" || secret == "your-super-secret-jwt-key-change-in-production" {
		log.Fatal("JWT_SECRET not set or using default value. Set it in environment variables.")
	}
	return secret
}

// ===== Инициализация =====

func initAuthClient(cfg *config.Config) {
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

// ===== Handlers =====

func metricsHandler(c *gin.Context) {
	// Простая метрика
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"uptime": time.Now().Unix() - startTime,
	})
}

func docsHandler(c *gin.Context) {
	// Здесь можно отдавать Swagger документацию
	c.JSON(http.StatusOK, gin.H{
		"swagger": "2.0",
		"info": gin.H{
			"title":   "Todolist API Gateway",
			"version": "1.0.0",
		},
		"paths": gin.H{
			"/auth/login": gin.H{
				"post": gin.H{
					"summary": "User login",
				},
			},
			// ... другие endpoints
		},
	})
}

func getUserInfoHandler(c *gin.Context) {
	// Возвращает информацию о текущем пользователе
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	roles, _ := c.Get("roles")
	session, _ := c.Get("session")
	jti, _ := c.Get("jti")
	tokenVersion, _ := c.Get("token_version")

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"roles":   roles,
		"session": session,
		"jti":     jti,
		"version": tokenVersion,
	})
}

// ===== Middleware =====

var startTime = time.Now().Unix()

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		end := time.Now()
		latency := end.Sub(start)

		if query != "" {
			path = path + "?" + query
		}

		userID, _ := c.Get("user_id")
		log.Printf("[GATEWAY] %3d | %13v | %15s | %-7s %s | user:%v",
			c.Writer.Status(),
			latency,
			c.ClientIP(),
			c.Request.Method,
			path,
			userID,
		)
	}
}

// ===== Подпись запросов =====

// createSignedProxy создает прокси с подписанными запросами
func createSignedProxy(target string) gin.HandlerFunc {
	targetURL, err := url.Parse(target)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	origDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.URL.Path = strings.TrimPrefix(req.URL.Path, getPathPrefix(req.URL.Path))

		if req.URL.Path == "" {
			req.URL.Path = "/"
		}

		// Добавляем заголовки аутентификации
		addAuthHeaders(req)

		// Добавляем подпись запроса
		signRequest(req)

		req.Header.Set("X-Forwarded-By", "todolist-gateway")
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		req.Header.Set("X-Forwarded-Proto", "http")
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
	}

	return gin.WrapH(proxy)
}

func getPathPrefix(path string) string {
	prefixes := []string{usersURL, tasksURL, analyticsURL, tasksByUserURL}
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return prefix
		}
	}
	return ""
}

func addAuthHeaders(req *http.Request) {
	// Если есть оригинальный Authorization header, сохраняем его
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		req.Header.Set("X-Original-Authorization", authHeader)
		req.Header.Del("Authorization")
	}

	// Добавляем заголовки из Gin контекста
	if ctx := req.Context().Value(gin.ContextKey); ctx != nil {
		if ginCtx, ok := ctx.(*gin.Context); ok {
			if userID, exists := ginCtx.Get("user_id"); exists {
				req.Header.Set("X-User-ID", fmt.Sprintf("%v", userID))
			}
			if roles, exists := ginCtx.Get("roles"); exists {
				req.Header.Set("X-User-Roles", fmt.Sprintf("%v", roles))
			}
			if session, exists := ginCtx.Get("session"); exists {
				req.Header.Set("X-Session-ID", fmt.Sprintf("%v", session))
			}
			if tokenVersion, exists := ginCtx.Get("token_version"); exists {
				req.Header.Set("X-Token-Version", fmt.Sprintf("%v", tokenVersion))
			}
			if jti, exists := ginCtx.Get("jti"); exists {
				req.Header.Set("X-JTI", fmt.Sprintf("%v", jti))
			}
		}
	}
}

func signRequest(req *http.Request) {
	timestamp := time.Now().Unix()

	// Создаем строку для подписи
	signString := fmt.Sprintf("%s\n%s\n%d\n%s",
		req.Method,
		req.URL.Path,
		timestamp,
		internalSecret,
	)

	// Вычисляем HMAC-SHA256 подпись
	h := hmac.New(sha256.New, []byte(internalSecret))
	h.Write([]byte(signString))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Добавляем заголовки подписи
	req.Header.Set("X-Gateway-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Gateway-Signature", signature)
	req.Header.Set("X-Gateway-Version", "1.0")
}

// ===== Вспомогательные функции =====

func buildTarget(host, port string) string {
	return "http://" + host + ":" + port
}

// Проверка подписи на стороне сервисов (пример для микросервисов)
func VerifyGatewaySignature(req *http.Request) bool {
	timestamp := req.Header.Get("X-Gateway-Timestamp")
	signature := req.Header.Get("X-Gateway-Signature")
	method := req.Method
	path := req.URL.Path

	if timestamp == "" || signature == "" {
		return false
	}

	// Проверяем время (запрос не старше 5 минут)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > 300 { // 5 минут
		return false
	}

	// Восстанавливаем подпись
	signString := fmt.Sprintf("%s\n%s\n%s\n%s",
		method,
		path,
		timestamp,
		internalSecret,
	)

	h := hmac.New(sha256.New, []byte(internalSecret))
	h.Write([]byte(signString))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// ===== gRPC вызовы =====

func callAuthService(c *gin.Context, cfg *config.Config, method string) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Services.Auth.Timeout)
	defer cancel()

	switch method {
	case "login":
		var req pb.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := authClient.Login(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	case "register":
		var req pb.RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := authClient.Register(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	case "verify_email":
		var req pb.VerifyEmailRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := authClient.VerifyEmail(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	case "get_access_token":
		var req pb.TokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := authClient.GetAccessToken(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	case "logout":
		var req pb.LogoutRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := authClient.Logout(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	case "logout_all":
		var req pb.LogoutAllRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := authClient.LogoutAll(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown method"})
	}
}

// Graceful shutdown
func cleanup() {
	if authConn != nil {
		authConn.Close()
	}
	log.Println("Gateway shutdown complete")
}
