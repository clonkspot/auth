package mwforum

import (
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
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

type authData struct {
	ID        int32
	LoginAuth string
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

// Tries to log the user in, setting a login cookie.
func (mwf *Connection) LoginHandler(username, password string, w http.ResponseWriter) error {
	auth, err := mwf.verifyPassword(username, password)
	if err != nil {
		return err
	}
	w.Header().Add("Set-Cookie", fmt.Sprintf("%slogin=%d:%s;secure;httponly;expires=Wed, 31-Dec-2031 00:00:00 GMT; ", mwf.CookiePrefix, auth.ID, auth.LoginAuth))
	return nil
}

var ErrUserNotFound = errors.New("mwforum: username does not exist")
var ErrInvalidPassword = errors.New("mwforum: invalid password")

// Verifies a user's password.
func (mwf *Connection) verifyPassword(username, password string) (*authData, error) {
	var row *sql.Row
	// username can be either an email address or the username
	if strings.ContainsRune(username, '@') {
		row = mwf.db.QueryRow("select id, password, salt, loginAuth from users where email = ?", username)
	} else {
		row = mwf.db.QueryRow("select id, password, salt, loginAuth from users where userName = ?", username)
	}
	var id int32
	var pwhash, salt, loginAuth string
	err := row.Scan(&id, &pwhash, &salt, &loginAuth)
	switch err {
	case sql.ErrNoRows:
		return nil, ErrUserNotFound
	default:
		return nil, err
	case nil: // ok
	}
	// compare password hashes
	if hashPassword(password, salt) != pwhash {
		return nil, ErrInvalidPassword
	}
	return &authData{ID: id, LoginAuth: loginAuth}, nil
}

// mwforum password hashing
func hashPassword(password, salt string) string {
	data := []byte(password + salt)
	for i := 0; i < 100000; i++ {
		hash := md5.Sum(data)
		data = hash[:]
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
