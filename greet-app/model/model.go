package model

//User struct
type User struct {
	UserName  string `json:"username"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Password  string `json:"password"`
	Token     string `json:"token"`
}

//ResponseResult struct
type ResponseResult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}

//JWT struct
type JWT struct {
	Token string `json:"token"`
}
