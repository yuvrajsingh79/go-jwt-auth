package controller

import (
	"encoding/json"
	"fmt"
	"greet-app/config/db"
	"greet-app/model"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Create the JWT key used to create the signature
var jwtKey = []byte("my_secret_key")

// Claims is a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	UserName  string `json:"username"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	jwt.StandardClaims
}

//RegisterHandler function does the signup of new user
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collection := db.GetConnection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	row := collection.QueryRow("select * from users where username=?", user.UserName)
	err = row.Scan(&user.UserName, &user.FirstName, &user.LastName, &user.Token, &user.Password)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
			if err != nil {
				res.Error = "Error While Hashing Password, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			user.Password = string(hash)
			_, err = collection.Exec("INSERT INTO users(username, password) VALUES(?, ?)", user.UserName, user.Password)
			if err != nil {
				res.Error = "Error While Creating User, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			res.Result = "Registration Successful"
			json.NewEncoder(w).Encode(res)
			return
		}
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	res.Result = "Username already Exists!!"
	json.NewEncoder(w).Encode(res)
	return
}

//LoginHandler function does a signin of the user and generates a token
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	collection := db.GetConnection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	var result model.User
	row := collection.QueryRow("select username, COALESCE(firstname, ''), COALESCE(lastname, ''), password, COALESCE(token, '') from users where username=?", user.UserName)
	err = row.Scan(&result.UserName, &result.FirstName, &result.LastName, &result.Password, &result.Token)
	if err != nil {
		res.Error = "Invalid username"
		json.NewEncoder(w).Encode(res)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	if err != nil {
		res.Error = "Invalid password"
		json.NewEncoder(w).Encode(res)
		return
	}
	// Declare the expiration time of the token, I am using 24 hours
	expirationTime := time.Now().Add(1440 * time.Minute)
	// Create the JWT claims, which includes the username, firstname, lastname and expiry time
	claims := &Claims{
		UserName:  result.UserName,
		FirstName: result.FirstName,
		LastName:  result.LastName,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		res.Error = "Error while generating token,Try again"
		json.NewEncoder(w).Encode(res)
		return
	}
	// we set the client cookie for "token" as the JWT we just generated
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	result.Token = tokenString
	result.Password = ""
	json.NewEncoder(w).Encode(result.Token)
	return
}

//UserDetails function returns the user's details using username and the request is Authorized using JWT token
func UserDetails(w http.ResponseWriter, r *http.Request) {
	//here we are usiing Authorization technique for demonstration purpose to validate the token
	tokenString := r.Header.Get("Authorization")
	tknStr := tokenString
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var result model.User
	result.UserName = claims.UserName
	result.FirstName = claims.FirstName
	result.LastName = claims.LastName
	json.NewEncoder(w).Encode(result)
	return
}

//ValidateAndRenewToken function validates the user token
func ValidateAndRenewToken(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Token is valid !")
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(1440 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the new token as the users `token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	var user model.User
	user.Token = tokenString
	json.NewEncoder(w).Encode(user.Token)
	return
}
