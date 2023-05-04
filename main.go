package main

import (
	"log"

	"com.example/database"
	"com.example/router"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"gorm.io/gorm"
)

var DB *gorm.DB

func CreateServer() *fiber.App {
	app := fiber.New()
	return app
}

func main() {
	database.ConnectToDB()
	app := CreateServer()
	app.Use(cors.New())

	router.SetupRoutes(app)

	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404)
	})

	log.Fatal(app.Listen(":3000"))
}
