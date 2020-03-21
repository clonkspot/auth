package main

import "github.com/gin-gonic/gin"

type loginPageData struct {
	Username   string
	ReturnURL  string
	loginError error
}

func showLoginPage(c *gin.Context, data loginPageData) {
	c.HTML(200, "login.html", gin.H{
		"Title":     "Login",
		"Username":  data.Username,
		"ReturnURL": data.ReturnURL,
		"Error":     data.loginError,
		"BasePath":  basePath,
	})
}

type indexPageData struct {
	Username string
}

func showIndexPage(c *gin.Context, data indexPageData) {
	c.HTML(200, "index.html", gin.H{
		"Title":    "OpenClonk",
		"Username": data.Username,
		"BasePath": basePath,
	})
}
