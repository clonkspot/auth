package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/clonkspot/auth/mwforum"
)

var mwforumDb = defaultValue(os.Getenv("MWFORUM_DB"), "/mwforum")
var mwforumCookiePrefix = defaultValue(os.Getenv("MWFORUM_COOKIE_PREFIX"), "mwf_")

var jwtConfigPath = defaultValue(os.Getenv("JWT_CONFIG"), "jwt.toml")

func defaultValue(val, def string) string {
	if val == "" {
		return def
	} else {
		return val
	}
}

func main() {
	mwf, err := mwforum.Connect(mwforumDb)
	if err != nil {
		log.Fatal(err)
	}
	mwf.CookiePrefix = mwforumCookiePrefix

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

	port := os.Getenv("PORT")
	log.Print("Listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
