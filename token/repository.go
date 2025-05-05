package token

import (
	"context"
	"fmt"
	"log"
)

type Repository interface {
	StoreToken(ctx context.Context, userId string, tok string) error
	GetToken(ctx context.Context, userId string) (string, error)
}

type InMemoryRepository struct {
	data map[string]string
}

func NewInMemoryRepository() Repository {
	return &InMemoryRepository{
		data: make(map[string]string),
	}
}

func (r *InMemoryRepository) StoreToken(ctx context.Context, userId string, tok string) error {
	log.Printf("userid: %s, tok: %s", userId, tok)
	r.data[userId] = tok
	return nil
}

func (r *InMemoryRepository) GetToken(ctx context.Context, userId string) (string, error) {
	tok, contains := r.data[userId]
	if !contains {
		return "", fmt.Errorf("token not found")
	}

	return tok, nil
}
