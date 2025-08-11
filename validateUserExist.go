package security

import (
	"fmt"

	"github.com/milbertk/class"
	"github.com/milbertk/databasesmng"
)

func DValidateUser(UID string) (exception bool, exist string, err error) {

	reader, err := class.NewJSONReader("./connection.json")
	println("jsn")
	println(reader)
	println(err)
	if err != nil {

		return false, "Error in read json", err
	}

	data := reader.GetJSON()
	fmt.Println("All data:", data)

	valueHost, ok1 := reader.GetValue("host")
	valuePort, ok2 := reader.GetValue("port")
	valueUser, ok3 := reader.GetValue("user")
	valuePass, ok4 := reader.GetValue("pass")
	valueDatabase, ok5 := reader.GetValue("database")

	if ok1 == false || ok2 == false || ok3 == false || ok4 == false ||
		ok5 == false {
		println("err IN")
		println(ok1)
		println(ok2)
		println(ok3)
		println(ok4)
		println(ok5)
		return false, "Error in reading data of conection", err
	}

	pgConn, err := databasesmng.NewPostgresConnector(valueHost, valuePort,
		valueUser, valuePass, valueDatabase)

	if err != nil {
		println("err IN 3")
		println(err)
		return false, "Postgree conection fail", err
	}

	defer pgConn.Close()
	fmt.Println("✅ Connected to PostgreSQL")

	var existUser int
	err = pgConn.DB.QueryRow("SELECT count(*) " +
		"from usfirebasedata where uid = '" + UID + "'").Scan(&existUser)
	if err != nil {
		return false, "unknow4", err
	}

	println("existe usre")
	println(existUser)
	if existUser == 0 {

		return false, "false", nil

	}

	println("existe usre")
	println(existUser)
	return true, "true", nil

}
