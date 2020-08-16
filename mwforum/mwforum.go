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
	TablePrefix  string
}

type User struct {
	ID       string
	Username string
	Realname string
	Email    string
	Admin    bool
	Groups   []string
}

type authData struct {
	ID        int32
	LoginAuth string
}

// Connect connects to the mwforum database specified by the dsn.
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

// AuthenticateUser checks whether a user is authenticated, returning that user.
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
	user.ID = parts[0]
	var loginAuth string
	var admin int
	err = mwf.db.QueryRow("select userName, email, realName, admin, loginAuth from "+mwf.TablePrefix+"users where id = ?", user.ID).Scan(&user.Username, &user.Email, &user.Realname, &admin, &loginAuth)
	if err != nil {
		return nil, fmt.Errorf("error fetching user: %w", err)
	}
	if loginAuth != parts[1] {
		return nil, ErrLoginCookieInvalid
	}
	if admin != 0 {
		user.Admin = true
	}
	user.Groups, err = mwf.fetchGroups(user.ID)
	if err != nil {
		return nil, fmt.Errorf("error fetching groups: %w", err)
	}
	return &user, nil
}

// fetchGroups retrieves all groups (by their title) of the user with the given id.
func (mwf *Connection) fetchGroups(id string) ([]string, error) {
	rows, err := mwf.db.Query("select title from "+mwf.TablePrefix+"groups join "+mwf.TablePrefix+"groupMembers on id = groupId where userId = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var group string
	var groups []string
	for rows.Next() {
		err := rows.Scan(&group)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
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
		row = mwf.db.QueryRow("select id, password, salt, loginAuth from "+mwf.TablePrefix+"users where email = ?", username)
	} else {
		row = mwf.db.QueryRow("select id, password, salt, loginAuth from "+mwf.TablePrefix+"users where userName = ?", username)
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
