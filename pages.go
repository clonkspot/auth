package main

import (
	"html/template"
	"io"
	"net/http"
)

var tmpl = template.Must(template.ParseGlob("templates/*.html"))
var loginPageTmpl = template.Must(template.Must(tmpl.Clone()).ParseFiles("templates/pages/login.html"))
var indexPageTmpl = template.Must(template.Must(tmpl.Clone()).ParseFiles("templates/pages/index.html"))

type loginPageData struct {
	ReturnURL  string
	loginError error
}

func showLoginPage(w http.ResponseWriter, data loginPageData) {
	w.Header().Add("Content-Type", "text/html; charset=utf8")
	w.WriteHeader(200)
	err := loginPageTmpl.ExecuteTemplate(w, "base.html", map[string]interface{}{
		"Title":     "Login",
		"ReturnURL": data.ReturnURL,
		"Error":     data.loginError,
		"BasePath":  basePath,
	})
	if err != nil {
		io.WriteString(w, err.Error())
	}
}

type indexPageData struct {
	Username string
}

func showIndexPage(w http.ResponseWriter, data indexPageData) {
	w.Header().Add("Content-Type", "text/html; charset=utf8")
	w.WriteHeader(200)
	err := indexPageTmpl.ExecuteTemplate(w, "base.html", map[string]interface{}{
		"Title":    "OpenClonk",
		"Username": data.Username,
		"BasePath": basePath,
	})
	if err != nil {
		io.WriteString(w, err.Error())
	}
}
