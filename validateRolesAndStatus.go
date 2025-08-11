package security

import (
	"database/sql"
	"fmt"

	"github.com/milbertk/databasesmng"
)

func DValidateStatus(UID string) (result bool, status string, err error) {
	db, err := databasesmng.CreateConnection()
	if err != nil {
		return false, "Connection error", err
	}

	var localstatus, active, disabled, emailverified string
	query := `SELECT localstatus, active, disabled, emailverified
			  FROM usfirebasedata
			  WHERE uid = $1`

	err = db.QueryRow(query, UID).Scan(&localstatus, &active, &disabled, &emailverified)

	if err == sql.ErrNoRows {
		return false, "User not found", nil
	} else if err != nil {
		return false, "Query error", fmt.Errorf("❌ Query failed: %v", err)
	}

	fmt.Println("✅ User fields found:")
	fmt.Printf("status: %s | active: %s | disabled: %s | verified: %s\n", localstatus, active, disabled, emailverified)

	if localstatus != "ACTIVE" {
		return false, "Inactive", fmt.Errorf("❌ User is inactive due to local status")
	}
	if active != "true" {
		return false, "Inactive", fmt.Errorf("❌ User is inactive (active flag)")
	}
	if disabled != "false" {
		return false, "Inactive", fmt.Errorf("❌ User is disabled")
	}

	return true, fmt.Sprintf("Status: %s", localstatus), nil
}
