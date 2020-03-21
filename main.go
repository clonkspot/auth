package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/clonkspot/auth/mwforum"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
)

var mwforumDb = defaultValue(os.Getenv("MWFORUM_DB"), "/mwforum")
var mwforumTablePrefix = defaultValue(os.Getenv("MWFORUM_TABLE_PREFIX"), "")
var mwforumCookiePrefix = defaultValue(os.Getenv("MWFORUM_COOKIE_PREFIX"), "mwf_")

// templatePath must contain a base.html template.
var templatePath = os.Getenv("TEMPLATE_PATH")

// basePath is needed when mounting the application on sub-paths.
// example: /api/auth
var basePath = os.Getenv("BASE_PATH")

var jwtConfigPath = defaultValue(os.Getenv("JWT_CONFIG"), "jwt.toml")
var discourseConfigPath = defaultValue(os.Getenv("DISCOURSE_CONFIG"), "")

func defaultValue(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

func main() {
	if templatePath == "" {
		log.Fatal("$TEMPLATE_PATH is not set")
	}

	mwf, err := mwforum.Connect(mwforumDb)
	if err != nil {
		log.Fatal(err)
	}
	mwf.CookiePrefix = mwforumCookiePrefix
	mwf.TablePrefix = mwforumTablePrefix

	r := gin.Default()
	templates, err := loadTemplates(templatePath)
	if err != nil {
		log.Fatal(err)
	}
	r.HTMLRender = templates

	r.GET("/", func(c *gin.Context) {
		user, err := mwf.AuthenticateUser(c.Request)
		if err != nil {
			log.Print(err)
			switch err {
			case mwforum.ErrNoLoginCookie, mwforum.ErrLoginCookieMalformed, mwforum.ErrLoginCookieInvalid:
				showLoginPage(c, loginPageData{ReturnURL: "/"})
			default:
				c.AbortWithError(500, err)
			}
			return
		}
		showIndexPage(c, indexPageData{Username: user.Username})
	})

	handleLogin(r, mwf)
	handleJwt(r, mwf)

	if discourseConfigPath != "" {
		handleDiscourseSSO(r, mwf)
	}

	port := os.Getenv("PORT")
	log.Print("Listening on port " + port)
	if os.Getenv("TLS_CERT") != "" {
		r.RunTLS(":"+port, os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	} else {
		r.Run(":" + port)
	}
}

// loadTemplates loads the HTML templates. dir is the base directory, for example "templates/clonkspot".
func loadTemplates(dir string) (multitemplate.Renderer, error) {
	r := multitemplate.NewRenderer()
	base, err := filepath.Glob(dir + "/*.html")
	if err != nil {
		return r, err
	}

	pages, err := filepath.Glob("templates/pages/*.html")
	if err != nil {
		return r, err
	}

	for _, page := range pages {
		templates := make([]string, len(base))
		copy(templates, base)
		templates = append(templates, page)
		r.AddFromFiles(filepath.Base(page), templates...)
	}

	return r, nil
}
