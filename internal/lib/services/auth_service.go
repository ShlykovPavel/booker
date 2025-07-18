package services

import (
	"booker/internal/lib/api/models/tokens"
	getUserDto "booker/internal/lib/api/models/users/get_user"
	"booker/internal/lib/jwt_tokens"
	"booker/internal/server/users"
	"booker/internal/storage/database/repositories/auth_db"
	"booker/internal/storage/database/repositories/users_db"
	"context"
	"errors"
	"log/slog"
	"time"
)

var ErrWrongPassword = errors.New("Password is incorrect ")

type AuthService struct {
	userRepo    users_db.UserRepository
	tokensRepo  auth_db.TokensRepository
	log         *slog.Logger
	secretKey   string
	JWTDuration time.Duration
}

func NewAuthService(db users_db.UserRepository, tokensRepo auth_db.TokensRepository, log *slog.Logger, secretKey string, jwtDuration time.Duration) *AuthService {
	return &AuthService{
		userRepo:    db,
		tokensRepo:  tokensRepo,
		log:         log,
		secretKey:   secretKey,
		JWTDuration: jwtDuration,
	}
}

func (a *AuthService) Authentication(user *getUserDto.AuthUser) (tokens.RefreshTokensDto, error) {
	const op = "server/users/auth/Authentification"
	log := a.log.With(
		slog.String("operation", op),
		slog.String("request email: ", user.Email))

	// Проверяем что пользователь есть в БД
	usr, err := a.userRepo.GetUser(context.Background(), user.Email)
	if err != nil {
		if errors.Is(err, users_db.ErrUserNotFound) {
			log.Debug("UserInfo not found", "user", user)
			return tokens.RefreshTokensDto{}, err
		}
		log.Error("Error while fetching user", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	// Проверяем что нам предоставили правильный пароль
	ok := users.ComparePassword(usr.PasswordHash, user.Password, log)
	if !ok {
		return tokens.RefreshTokensDto{}, ErrWrongPassword
	}
	accessToken, err := jwt_tokens.CreateAccessToken(usr.ID, a.secretKey, usr.Role, a.JWTDuration, a.log)
	if err != nil {
		log.Error("Error while creating access token", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	refreshToken, err := jwt_tokens.CreateRefreshToken(a.log)
	if err != nil {
		log.Error("Error while creating refresh token", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	err = a.tokensRepo.DbPutTokens(context.Background(), usr.ID, refreshToken)
	if err != nil {
		log.Error("Error while storing tokens", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	return tokens.RefreshTokensDto{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *AuthService) RefreshTokens(tokensForRefresh *tokens.RefreshTokensDto) (tokens.RefreshTokensDto, error) {
	const op = "internal/lib/services/auth_service.go/RefreshTokens"
	log := a.log.With(
		slog.String("operation", op),
	)
	tokenData, err := a.tokensRepo.DbGetTokens(context.Background(), tokensForRefresh.RefreshToken)
	if err != nil {
		log.Error("Error while fetching tokensForRefresh", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	accessToken, err := jwt_tokens.CreateAccessToken(tokenData.UserId, a.secretKey, tokenData.UserRole, a.JWTDuration, a.log)
	if err != nil {
		log.Error("Error while creating access token", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	refreshToken, err := jwt_tokens.CreateRefreshToken(a.log)
	if err != nil {
		log.Error("Error while creating refresh token", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	err = a.tokensRepo.DbUpdateTokens(context.Background(), tokenData.UserId, refreshToken, tokensForRefresh.RefreshToken)
	if err != nil {
		log.Error("Error while storing tokensForRefresh", "err", err)
		return tokens.RefreshTokensDto{}, err
	}
	return tokens.RefreshTokensDto{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *AuthService) Logout(tokens *tokens.LogoutRequest) error {
	const op = "server/users/auth/Logout"
	log := a.log.With(
		slog.String("operation", op))
	_, err := a.tokensRepo.DbGetTokens(context.Background(), tokens.RefreshToken)
	if err != nil {
		log.Error("Error while fetching tokens", "err", err)
		return err
	}
	err = a.tokensRepo.DbDeleteToken(context.Background(), tokens.RefreshToken)
	if err != nil {
		log.Error("Error while deleting tokens", "err", err)
		return err
	}
	return nil

}
