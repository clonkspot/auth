package main

import (
	"github.com/clonkspot/auth/mwforum"
	"net/http"
	"encoding/json"
)

type loginRequest struct {
	Username string
	Password string
}

func handleLogin(mwf *mwforum.Connection) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		var req loginRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := mwf.LoginHandler(req.Username, req.Password, w); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			res, _ := json.Marshal(map[string]string {
				"message": err.Error(),
			})
			w.Write(res)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
