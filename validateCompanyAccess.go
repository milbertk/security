package security

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/milbertk/databasesmng"
)

// DValidateCompanyAccess checks, directly against the MAIN database (usersAK),
// whether a user is linked to a company with a management role (OWNER /
// MANAGER), and also returns the user's official e-mail from
// public.usfirebasedata.
//
// It uses databasesmng.CreateConnection() — the SAME connection the original
// security validators use (DValidateStatus / DValidateUser) — because company
// membership and user identity live in the main database, not in shao. A user
// is linked to a company here, and only then can be used across the different
// platforms (shao, etc.).
//
// Access is granted when ANY of the following is true:
//  1. The user has an active row in public.company_users with role OWNER or MANAGER.
//  2. The user is the registered owner of the company in public.companies
//     (companies.owner_firebase_uid = userID), even if no row exists in
//     public.company_users.
//
// Returns:
//   - allowed: true only for OWNER / MANAGER
//   - role:    the resolved role (may be a non-management role, for context)
//   - email:   the official e-mail from public.usfirebasedata (may be empty
//     if the user has no row there); NEVER taken from the frontend
//   - err:     any connection or query error
func DValidateCompanyAccess(companyID string, userID string) (allowed bool, role string, email string, err error) {
	companyID = strings.TrimSpace(companyID)
	userID = strings.TrimSpace(userID)

	if companyID == "" {
		return false, "", "", fmt.Errorf("companyId is required")
	}
	if userID == "" {
		return false, "", "", fmt.Errorf("userId is required")
	}

	// Same connection as the original security validators (main database).
	db, err := databasesmng.CreateConnection()
	if err != nil {
		return false, "", "", fmt.Errorf("connection error: %v", err)
	}

	println("Validate company access")
	println(companyID, userID)

	// Gather every possible role source for this (company, user) and pick the
	// strongest match deterministically via `priority`:
	//   1 = OWNER from companies.owner_firebase_uid
	//   2 = role from company_users (active rows only)
	//
	// The official e-mail always comes from public.usfirebasedata, joined by
	// uid = userID, so it is trustworthy regardless of the matched source.
	query := `
		SELECT access.role, access.priority, COALESCE(uf.email, '') AS email
		FROM (
			SELECT 'OWNER'::text AS role, 1 AS priority
			FROM public.companies
			WHERE company_id = $1
			  AND owner_firebase_uid = $2
			UNION ALL
			SELECT role, 2 AS priority
			FROM public.company_users
			WHERE company_id = $1
			  AND user_id = $2
			  AND active = true
		) AS access
		LEFT JOIN public.usfirebasedata uf
			ON uf.uid = $2
		ORDER BY access.priority ASC
		LIMIT 1
	`

	var priority int
	err = db.QueryRow(query, companyID, userID).Scan(&role, &priority, &email)

	if err == sql.ErrNoRows {
		// No match in either source — user has no relationship with this company.
		return false, "", "", nil
	} else if err != nil {
		return false, "", "", fmt.Errorf("failed to validate company access: %v", err)
	}

	role = strings.ToUpper(strings.TrimSpace(role))
	email = strings.TrimSpace(email)

	switch role {
	case "OWNER", "MANAGER":
		return true, role, email, nil
	default:
		// User exists in company_users but with a non-management role
		// (e.g. USER, SUPPORT). Return role and email for context, deny access.
		return false, role, email, nil
	}
}
