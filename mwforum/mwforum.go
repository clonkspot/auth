package mwforum

import (
	"database/sql"
	"errors"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	"strings"
)

type Connection struct {
	db           *sql.DB
	CookiePrefix string
}

type User struct {
	Username string
	Email    string
}

// Connects to the mwforum database specified by the dsn.
func Connect(dsn string) (*Connection, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	return &Connection{db: db}, nil
}

var ErrNoLoginCookie = errors.New("mwforum: no login cookie")
var ErrLoginCookieMalformed = errors.New("mwforum: malformed login cookie")
var ErrLoginCookieInvalid = errors.New("mwforum: invalid login cookie")

// Checks whether a user is authenticated, returning that user.
func (mwf *Connection) AuthenticateUser(req *http.Request) (*User, error) {
	cookie, err := req.Cookie(mwf.CookiePrefix + "login")
	if err != nil {
		return nil, ErrNoLoginCookie
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 2 {
		return nil, ErrLoginCookieMalformed
	}
	var user User
	var loginAuth string
	err = mwf.db.QueryRow("select userName, email, loginAuth from users where id = ?", parts[0]).Scan(&user.Username, &user.Email, &loginAuth)
	if err != nil {
		return nil, err
	}
	if loginAuth != parts[1] {
		return nil, ErrLoginCookieInvalid
	}
	return &user, nil
}
