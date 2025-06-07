package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}

type JWTManager interface {
	GenerateAccessToken(userId string) (string, error)
	GenerateRefreshToken(userId string) (string, error)
	ValidateToken(tokenString string) (*Claims, error)
	GetAccessTokenExp() time.Duration
	GetRefreshTokenExp() time.Duration
}

func NewJWTManager(issuer, secretKey string, accessTokenExp, refreshTokenExp time.Duration) JWTManager {
	return &jwtManagerImpl{
		issuer:          issuer,
		secretKey:       []byte(secretKey),
		accessTokenExp:  accessTokenExp,
		refreshTokenExp: refreshTokenExp,
	}
}

type jwtManagerImpl struct {
	issuer          string
	secretKey       []byte
	accessTokenExp  time.Duration
	refreshTokenExp time.Duration
}

func (manager *jwtManagerImpl) GetAccessTokenExp() time.Duration {
	return manager.accessTokenExp
}

func (manager *jwtManagerImpl) GetRefreshTokenExp() time.Duration {
	return manager.refreshTokenExp
}

func (manager *jwtManagerImpl) GenerateAccessToken(userId string) (string, error) {
	return manager.generateToken(userId, manager.accessTokenExp)
}

func (manager *jwtManagerImpl) GenerateRefreshToken(userId string) (string, error) {
	return manager.generateToken(userId, manager.refreshTokenExp)
}

func (manager *jwtManagerImpl) generateToken(userId string, exp time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    manager.issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(exp)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(manager.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (manager *jwtManagerImpl) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return manager.secretKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, fmt.Errorf("invalid token signature")
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token is expired")
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
