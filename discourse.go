package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/clonkspot/auth/mwforum"
	"github.com/gin-gonic/gin"
)

// DiscourseConfig is the structure of the discourse.toml configuration file.
type DiscourseConfig struct {
	Secret    string
	ReturnURL string
}

// loadDiscourseConfig loads the discourse.toml config file at `path`.
func loadDiscourseConfig(path string) (*DiscourseConfig, error) {
	var cfg DiscourseConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("Parse error in %s: %s", path, err.Error())
	}
	return &cfg, nil
}

// handleDiscourseSSO returns a request handler for Discourse SSO.
// See https://meta.discourse.org/t/official-single-sign-on-for-discourse-sso/13045
func handleDiscourseSSO(r gin.IRouter, mwf *mwforum.Connection) {
	cfg, err := loadDiscourseConfig(discourseConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	r.GET("/discourse", func(c *gin.Context) {
		parsed := c.Request.URL.Query()
		// 1. Validate the signature, ensure that HMAC-SHA256 of sso_secret, PAYLOAD is equal to the sig
		sig, err := hex.DecodeString(parsed.Get("sig"))
		if err != nil {
			c.AbortWithError(400, fmt.Errorf("invalid sig hex string\n%w", err))
			return
		}
		h := hmac.New(sha256.New, []byte(cfg.Secret))
		h.Write([]byte(parsed.Get("sso")))
		if !hmac.Equal(h.Sum(nil), sig) {
			c.AbortWithError(400, fmt.Errorf("invalid signature"))
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(parsed.Get("sso"))
		if err != nil {
			c.AbortWithError(400, fmt.Errorf("invalid base64 in sso\n%w", err))
			return
		}
		decodedValues, err := url.ParseQuery(string(decoded))
		if err != nil {
			c.AbortWithError(400, fmt.Errorf("invalid query string in sso\n%w", err))
			return
		}
		// 2. Perform whatever authentication it has to
		user, err := mwf.AuthenticateUser(c.Request)
		if err != nil {
			// The user will have to enter username and password.
			showLoginPage(c, loginPageData{ReturnURL: c.Request.URL.EscapedPath() + "?" + c.Request.URL.RawQuery})
			return
		}
		// 3. Create a new payload with nonce, email, external_id and optionally (username, name)
		payload := url.Values{}
		payload.Set("nonce", decodedValues.Get("nonce"))
		payload.Set("email", user.Email)
		payload.Set("external_id", user.ID)
		payload.Set("username", user.Username)
		payload.Set("name", user.Realname)
		payload.Set("groups", strings.Join(user.Groups, ","))
		if user.Admin {
			payload.Set("admin", "true")
		} else {
			payload.Set("admin", "false")
		}
		// 4. Base64 encode the payload
		encodedPayload := base64.StdEncoding.EncodeToString([]byte(payload.Encode()))
		// 5. Calculate a HMAC-SHA256 hash of the payload using sso_secret as the key and Base64 encoded payload as text
		h.Reset()
		h.Write([]byte(encodedPayload))
		outSig := hex.EncodeToString(h.Sum(nil))
		// 6. Redirect back to http://discourse_site/session/sso_login?sso=payload&sig=sig
		c.Redirect(302, cfg.ReturnURL+"?sso="+encodedPayload+"&sig="+outSig)
	})
}
