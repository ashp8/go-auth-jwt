package models

import "github.com/dgrijalva/jwt-go"

type User struct {
	Base
	Email    string `json:"email" gorm:"unique"`
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
}

type UserErrors struct {
	Err      bool   `json:"error"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password`
}

type Claims struct {
	jwt.StandardClaims
	ID uint `gorm:"primaryKey"`
}
