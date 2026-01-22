package main

import (
	"api-getaway/app/internal/config"
	"context"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	pb "github.com/s10n41k/protos/gen/go/sso" // gRPC stubs
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

func main() {
	cfg := config.Load()
	r := gin.Default()

	// ===== HTTP → HTTP сервисы =====
	createProxy(r, usersURL, buildTarget(cfg.Services.Users.Host, cfg.Services.Users.Port))
	createProxy(r, tasksURL, buildTarget(cfg.Services.Tasks.Host, cfg.Services.Tasks.Port))
	createProxy(r, tasksByUserURL, buildTarget(cfg.Services.Tasks.Host, cfg.Services.Tasks.Port))
	createProxy(r, analyticsURL, buildTarget(cfg.Services.Analytics.Host, cfg.Services.Analytics.Port))

	// ===== HTTP → gRPC (auth-service) =====
	// Проксирование всех auth ручек через HTTP
	r.POST(loginMethod, func(c *gin.Context) { callAuthService(c, cfg, "login") })
	r.POST(registerMethod, func(c *gin.Context) { callAuthService(c, cfg, "register") })
	r.POST(verifyEmailMethod, func(c *gin.Context) { callAuthService(c, cfg, "verify_email") })
	r.POST(getAccessToken, func(c *gin.Context) { callAuthService(c, cfg, "get_access_token") })
	r.POST(logoutMethod, func(c *gin.Context) { callAuthService(c, cfg, "logout") })
	r.POST(logoutAllMethod, func(c *gin.Context) { callAuthService(c, cfg, "logout_all") })

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "gateway ok"})
	})

	log.Println("Gateway started on port " + cfg.Listen.Port)
	r.Run(cfg.Listen.BindIP + ":" + cfg.Listen.Port)
}

// buildTarget собирает URL из хоста и порта
func buildTarget(host, port string) string {
	return "http://" + host + ":" + port
}

// createProxy проксирует все запросы с префикса на HTTP сервис
func createProxy(router *gin.Engine, prefix, target string) {
	targetURL, err := url.Parse(target)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		req.Header.Set("X-Forwarded-By", "todolist-gateway")
	}

	router.Any(prefix+"/*path", gin.WrapH(proxy))
}

// callAuthService делает HTTP → gRPC вызов к auth-service
func callAuthService(c *gin.Context, cfg *config.Config, method string) {
	conn, err := grpc.Dial(cfg.Services.Auth.Host+":"+cfg.Services.Auth.Port, grpc.WithInsecure())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot connect to auth service"})
		return
	}
	defer conn.Close()

	client := pb.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Services.Auth.Timeout)
	defer cancel()

	switch method {
	case "login":
		var req pb.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		res, err := client.Login(ctx, &req)
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
		res, err := client.Register(ctx, &req)
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
		res, err := client.VerifyEmail(ctx, &req)
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
		res, err := client.GetAccessToken(ctx, &req)
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
		res, err := client.Logout(ctx, &req)
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
		res, err := client.LogoutAll(ctx, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)

	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown method"})
	}
}
