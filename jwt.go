package main

import (
	"encoding/base64"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/clonkspot/auth/mwforum"
	"github.com/dgrijalva/jwt-go"
	"io"
	"log"
	"net/http"
	"time"
)

type JwtSite struct {
	URL        string
	Key        string
	Exp        string
	decodedKey []byte
	decodedExp time.Duration
}

type JwtConfig struct {
	Issuer string
	Sites  map[string]JwtSite
}

func loadJwtConfig(path string) (*JwtConfig, error) {
	var cfg JwtConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("Parse error in %s: %s", path, err.Error())
	}
	for name, site := range cfg.Sites {
		var err error
		if site.decodedKey, err = base64.StdEncoding.DecodeString(site.Key); err != nil {
			return nil, fmt.Errorf("Invalid key for %s: %s", name, err.Error())
		}
		if site.decodedExp, err = time.ParseDuration(site.Exp); err != nil {
			return nil, fmt.Errorf("Invalid exp for %s: %s", name, err.Error())
		}
		cfg.Sites[name] = site
	}
	return &cfg, nil
}

func handleJwt(mwf *mwforum.Connection) func(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadJwtConfig(jwtConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// Expect a JWT in the request.
		requestToken := r.URL.RawQuery
		reqClaims := jwt.StandardClaims{}
		var site *JwtSite
		reqToken, err := jwt.ParseWithClaims(requestToken, &reqClaims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			if s, ok := cfg.Sites[reqClaims.Issuer]; ok {
				site = &s
				return site.decodedKey, nil
			}
			return nil, fmt.Errorf("Unknown issuer: %s", reqClaims.Issuer)
		})
		if err != nil || !reqToken.Valid {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		// Now, find our local user.
		user, err := mwf.AuthenticateUser(r)
		if err != nil {
			// The user will have to enter username and password.
			showLoginPage(w, loginPageData{ReturnURL: r.URL.EscapedPath() + "?" + r.URL.RawQuery})
			return
		}

		// Generate token.
		resToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss":   cfg.Issuer,
			"aud":   reqClaims.Issuer,
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(site.decodedExp).Unix(),
			"jti":   reqClaims.Id,
			"sub":   user.Username,
			"email": user.Email,
		})
		ss, err := resToken.SignedString(site.decodedKey)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
		}
		// Redirect back to requester.
		w.Header().Add("Location", site.URL+"?"+ss)
		w.WriteHeader(302)
	}
}
