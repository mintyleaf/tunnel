package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const DefaultExpirationTime = 24 * time.Hour

var (
	ErrTokenNotFound = errors.New("token not found or already used")
	ErrTokenExpired  = errors.New("token has expired")
)

func InitTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS one_time_tokens (
			token TEXT NOT NULL PRIMARY KEY,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);
	`)
	return err
}

func (s AuthService) NewToken() (string, error) {
	newToken, err := generateToken()
	if err != nil {
		return "", err
	}

	expirationTime := time.Now().Add(DefaultExpirationTime)

	_, err = s.DB.Exec(
		`INSERT INTO one_time_tokens (token, expires_at) VALUES ($1, $2)`,
		newToken,
		expirationTime,
	)
	if err != nil {
		return "", err
	}

	return newToken, nil
}

func (s AuthService) ValidateAndBurnToken(token string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var expiresAt time.Time

	row := tx.QueryRow(`SELECT expires_at
			FROM one_time_tokens
			WHERE token = $1
			FOR UPDATE`,
		token,
	)

	err = row.Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenNotFound
		}
		return err
	}

	if time.Now().After(expiresAt) {
		_, _ = tx.Exec(`DELETE
				FROM one_time_tokens
				WHERE token = $1
			`, token)
		tx.Commit()
		return ErrTokenExpired
	}

	res, err := tx.Exec(`DELETE
			FROM one_time_tokens
			WHERE token = $1`,
		token)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrTokenNotFound
	}

	return tx.Commit()
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
