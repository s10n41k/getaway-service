package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
	"time"
)

var (
	jwtSecret = []byte("your-super-secret-jwt-key-change-in-production")
)

type AuthMiddleware struct {
	secret []byte
}

func NewAuthMiddleware(secret string) *AuthMiddleware {
	return &AuthMiddleware{secret: []byte(secret)}
}

func (m *AuthMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем public endpoints
		if isPublicEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Извлекаем токен
		tokenString := extractToken(c.Request)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			c.Abort()
			return
		}

		// Верифицируем токен
		claims, err := m.verifyToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Добавляем claims в контекст
		c.Set("claims", claims)

		if userID, ok := claims["sub"].(string); ok {
			c.Set("user_id", userID)
		}
		if roles, ok := claims["roles"].(string); ok {
			c.Set("roles", roles)
		}
		if session, ok := claims["session"].(string); ok {
			c.Set("session", session)
		}
		if ver, ok := claims["ver"].(float64); ok {
			c.Set("token_version", int(ver))
		}
		if jti, ok := claims["jti"].(string); ok {
			c.Set("jti", jti)
		}

		c.Next()
	}
}

func (m *AuthMiddleware) verifyToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return m.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Проверяем expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return nil, jwt.ErrTokenExpired
			}
		}
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}

func extractToken(r *http.Request) string {
	// Из заголовка Authorization
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}

	// Из query параметра
	token := r.URL.Query().Get("token")
	if token != "" {
		return token
	}

	// Из cookie
	cookie, err := r.Cookie("access_token")
	if err == nil {
		return cookie.Value
	}

	return ""
}

func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/health",
		"/auth/login",
		"/auth/register",
		"/auth/verify-email",
		"/auth/get-access-token",
		"/metrics",
		"/docs",
		"/swagger",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}
	return false
}
