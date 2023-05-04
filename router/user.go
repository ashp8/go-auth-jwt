package router

import (
	"math/rand"
	"os"
	"time"

	db "com.example/database"
	"com.example/models"
	"com.example/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte(os.Getenv("PRIV_KEY"))

func SetupUserRoutes() {
	USER.Post("/signup", createUser)
	USER.Post("/signin", LoginUser)
	USER.Get("/get-access-token", GetAccessToken)

	privUser := USER.Group("/private")
	privUser.Use(utils.SecureAuth())
	privUser.Get("/user", GetUserData)
}

func LoginUser(c *fiber.Ctx) error {
	type LoginInput struct {
		Identity string `json:"identity"`
		Password string `json:"password"`
	}
	input := new(LoginInput)

	if err := c.BodyParser(input); err != nil {
		return c.JSON(fiber.Map{
			"error": true,
			"input": "Please review your input!",
		})
	}

	u := new(models.User)

	if res := db.DB.Where(&models.User{Email: input.Identity}).Or(&models.User{Username: input.Identity}).First(&u); res.RowsAffected <= 0 {
		return c.JSON(fiber.Map{
			"error":   true,
			"general": "Invalid Credentials.",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input.Password)); err != nil {
		return c.JSON(fiber.Map{"error": true, "general": "Invalid Credentials."})
	}

	accessToken, refreshToken := utils.GenerateTokens(u.UUID.String())
	accessCookie, refreshCookie := utils.GetAuthCookies(accessToken, refreshToken)

	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func createUser(c *fiber.Ctx) error {
	u := new(models.User)

	if err := c.BodyParser(u); err != nil {
		return c.JSON(fiber.Map{
			"error": true,
			"input": "Please review your input",
		})
	}

	errors := utils.ValidateRegister(u)
	if errors.Err {
		return c.JSON(errors)
	}

	if count := db.DB.Where(&models.User{Email: u.Email}).First(new(models.User)).RowsAffected; count > 0 {
		errors.Err, errors.Email = true, "Email is Already registered!"
	}

	if count := db.DB.Where(&models.User{Username: u.Username}).First(new(models.User)).RowsAffected; count > 0 {
		errors.Err, errors.Username = true, "Username is Already registered!"
	}

	if errors.Err {
		return c.JSON(errors)
	}

	password := []byte(u.Password)

	hashedPassword, err := bcrypt.GenerateFromPassword(
		password,
		rand.Intn(bcrypt.MaxCost-bcrypt.MinCost)+bcrypt.MinCost,
	)
	if err != nil {
		panic(err)
	}
	u.Password = string(hashedPassword)

	if err := db.DB.Create(&u).Error; err != nil {
		return c.JSON(fiber.Map{
			"error":   true,
			"general": "Something went wrong, please try again later!",
		})
	}

	accessToken, refreshToken := utils.GenerateTokens(u.UUID.String())
	accessCookie, refreshCookie := utils.GetAuthCookies(accessToken, refreshToken)
	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func GetUserData(c *fiber.Ctx) error {
	id := c.Locals("id")
	u := new(models.User)

	if res := db.DB.Where("uuid = ?", id).First(&u); res.RowsAffected <= 0 {
		return c.JSON(fiber.Map{"error": true, "general": "Cannot find the User."})
	}

	return c.JSON(u)
}

func GetAccessToken(c *fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")

	refreshClaims := new(models.Claims)
	token, _ := jwt.ParseWithClaims(refreshToken, refreshClaims,
		func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if res := db.DB.Where(
		"expires_at = ? AND issued_at = ? AND issuer = ?",
		refreshClaims.ExpiresAt, refreshClaims.IssuedAt, refreshClaims.Issuer,
	).First(&models.Claims{}); res.RowsAffected <= 0 {
		// no such refresh token exist in the database
		c.ClearCookie("access_token", "refresh_token")
		return c.SendStatus(fiber.StatusForbidden)
	}

	if token.Valid {
		if refreshClaims.ExpiresAt < time.Now().Unix() {
			// refresh token is expired
			c.ClearCookie("access_token", "refresh_token")
			return c.SendStatus(fiber.StatusForbidden)
		}
	} else {
		// malformed refresh token
		c.ClearCookie("access_token", "refresh_token")
		return c.SendStatus(fiber.StatusForbidden)
	}

	_, accessToken := utils.GenerateAccessClaims(refreshClaims.Issuer)

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})

	return c.JSON(fiber.Map{"access_token": accessToken})
}
