package db

import (
	"database/sql"

	//for mysql
	_ "github.com/go-sql-driver/mysql"
)

//GetConnection function establishes a connection to mysql db
func GetConnection() (db *sql.DB) {
	dbDriver := "mysql"
	dbUser := "root"
	dbPass := "test"
	dbName := "go_app"
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	return db
}
