package oauth

type ProviderUser struct {
	Provider string `json:"provider"`
	Id       string `json:"id" binding:"required"`
	Email    string `json:"email" binding:"required"`
}
