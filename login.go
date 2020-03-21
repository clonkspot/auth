package main

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/clonkspot/auth/mwforum"
	"github.com/gin-gonic/gin"
)

type loginRequest struct {
	Username  string `form:"username"`
	Password  string `form:"password"`
	ReturnURL string `form:"returnURL"`
}

// handleLogin handles the /login route.
// GET  => shows the login page
// POST => handles login via POSTing JSON or a form.
func handleLogin(r gin.IRouter, mwf *mwforum.Connection) {
	r.GET("/login", func(c *gin.Context) {
		c.Redirect(302, "/")
	})

	r.POST("/login", func(c *gin.Context) {
		var req loginRequest
		switch c.GetHeader("Content-Type") {
		case "application/json":
			if c.BindJSON(&req) == nil {
				if err := mwf.LoginHandler(req.Username, req.Password, c.Writer); err != nil {
					c.JSON(http.StatusForbidden, map[string]string{
						"message": err.Error(),
					})
					return
				}
				c.Status(http.StatusNoContent)
			}
		case "application/x-www-form-urlencoded":
			if c.Bind(&req) == nil {
				if err := mwf.LoginHandler(req.Username, req.Password, c.Writer); err != nil {
					showLoginPage(c, loginPageData{Username: req.Username, loginError: err, ReturnURL: "/"})
					return
				}
				returnURL := "/"
				if u, err := url.Parse(req.ReturnURL); err != nil {
					// Don't allow redirects outside of auth.
					returnURL = u.EscapedPath()
					if u.ForceQuery || u.RawQuery != "" {
						returnURL += "?" + u.RawQuery
					}
					if u.Fragment != "" {
						returnURL += "#" + u.Fragment
					}
				}
				c.Redirect(302, req.ReturnURL)
			}
		default:
			c.Status(http.StatusUnsupportedMediaType)
			return
		}
	})

	r.GET("/logout", func(c *gin.Context) {
		c.Writer.Header().Add("Set-Cookie", fmt.Sprintf("%slogin=deleted;secure;httponly;expires=Thu, 01 Jan 1970 00:00:00 GMT; ", mwf.CookiePrefix))
		c.Redirect(302, "/")
	})
}
