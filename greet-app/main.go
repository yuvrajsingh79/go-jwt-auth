package main

import (
	"greet-app/controller"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", controller.RegisterHandler).
		Methods("POST")
	r.HandleFunc("/login", controller.LoginHandler).
		Methods("POST")
	r.HandleFunc("/validateToken", controller.ValidateAndRenewToken).
		Methods("GET")
	r.HandleFunc("/userDetails", controller.UserDetails).
		Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
}
