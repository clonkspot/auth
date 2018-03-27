package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/clonkspot/auth/mwforum"
)

type loginRequest struct {
	Username  string
	Password  string
	ReturnURL string
}

// handleLogin handles the /login route.
// GET  => shows the login page
// POST => handles login via POSTing JSON or a form.
func handleLogin(mwf *mwforum.Connection) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Header().Add("Location", "/")
			w.WriteHeader(302)
		case "POST":
			var req loginRequest
			switch r.Header.Get("Content-Type") {
			case "application/json":
				dec := json.NewDecoder(r.Body)
				if err := dec.Decode(&req); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if err := mwf.LoginHandler(req.Username, req.Password, w); err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					res, _ := json.Marshal(map[string]string{
						"message": err.Error(),
					})
					w.Write(res)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			case "application/x-www-form-urlencoded":
				req.Username = r.PostFormValue("username")
				req.Password = r.PostFormValue("password")
				req.ReturnURL = r.PostFormValue("returnURL")
				if err := mwf.LoginHandler(req.Username, req.Password, w); err != nil {
					showLoginPage(w, loginPageData{
						ReturnURL:  req.ReturnURL,
						loginError: err,
					})
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
				w.Header().Add("Location", req.ReturnURL)
				w.WriteHeader(302)
			default:
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func handleLogout(mwf *mwforum.Connection) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", fmt.Sprintf("%slogin=deleted;secure;httponly;expires=Thu, 01 Jan 1970 00:00:00 GMT; ", mwf.CookiePrefix))
		w.Header().Add("Location", "/")
		w.WriteHeader(302)
	}
}
