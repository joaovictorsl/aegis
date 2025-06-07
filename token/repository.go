package token

import (
	"context"
	"fmt"
)

type Repository interface {
	StoreToken(ctx context.Context, userId string, tok string) error
	SelectToken(ctx context.Context, userId string) (string, error)
}

type inMemoryRepository struct {
	data map[string]string
}

func NewInMemoryRepository() Repository {
	return &inMemoryRepository{
		data: make(map[string]string),
	}
}

func (r *inMemoryRepository) StoreToken(ctx context.Context, userId string, tok string) error {
	r.data[userId] = tok
	return nil
}

func (r *inMemoryRepository) SelectToken(ctx context.Context, userId string) (string, error) {
	tok, contains := r.data[userId]
	if !contains {
		return "", fmt.Errorf("token not found")
	}

	return tok, nil
}
