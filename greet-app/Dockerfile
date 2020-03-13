FROM golang:latest

LABEL maintainer="Yuvraj Singh <singhyuvraj79@gmail.com>"

RUN mkdir $GOPATH/src/greet-app
RUN go get github.com/dgrijalva/jwt-go
RUN go get golang.org/x/crypto/bcrypt
RUN go get github.com/gorilla/mux
RUN go get github.com/go-sql-driver/mysql
RUN go get database/sql

ADD . $GOPATH/src/greet-app
WORKDIR $GOPATH/src/greet-app

RUN go build -o /app/main .

CMD ["/app/main"]
EXPOSE 8080
