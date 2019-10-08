package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/clonkspot/auth/mwforum"
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user, err := mwf.AuthenticateUser(r)
		if err != nil {
			switch err {
			case mwforum.ErrNoLoginCookie, mwforum.ErrLoginCookieMalformed, mwforum.ErrLoginCookieInvalid:
				showLoginPage(w, loginPageData{ReturnURL: "/"})
			default:
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
			}
			return
		}
		showIndexPage(w, indexPageData{Username: user.Username})
	})

	http.HandleFunc("/jwt", handleJwt(mwf))
	http.HandleFunc("/login", handleLogin(mwf))
	http.HandleFunc("/logout", handleLogout(mwf))

	if discourseConfigPath != "" {
		http.HandleFunc("/discourse", handleDiscourseSSO(mwf))
	}

	port := os.Getenv("PORT")
	log.Print("Listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
