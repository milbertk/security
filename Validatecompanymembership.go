package security

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/milbertk/databasesmng"
)

// DValidateCompanyMembership checks, against the MAIN database (usersAK),
// whether a user simply BELONGS to a company — with ANY role — and returns the
// user's official e-mail from public.usfirebasedata.
//
// Unlike DValidateCompanyAccess (which requires OWNER / MANAGER), this one only
// confirms that the user has a relationship with the company:
//  1. the user is the registered owner in public.companies, OR
//  2. the user has an active row in public.company_users (any role).
//
// It uses databasesmng.CreateConnection() — the same connection the other
// security validators use — because membership and identity live in the main
// database, not in shao.
//
// Returns:
//   - belongs: true if the user belongs to the company (any role)
//   - role:    the resolved role (OWNER, or whatever company_users holds)
//   - email:   the official e-mail from public.usfirebasedata (may be empty);
//     NEVER taken from the frontend
//   - err:     any connection or query error
func DValidateCompanyMembership(companyID string, userID string) (belongs bool, role string, email string, err error) {
	companyID = strings.TrimSpace(companyID)
	userID = strings.TrimSpace(userID)

	if companyID == "" {
		return false, "", "", fmt.Errorf("companyId is required")
	}
	if userID == "" {
		return false, "", "", fmt.Errorf("userId is required")
	}

	db, err := databasesmng.CreateConnection()
	if err != nil {
		return false, "", "", fmt.Errorf("connection error: %v", err)
	}

	println("Validate company membership")
	println(companyID, userID)

	// Same two sources as DValidateCompanyAccess, with `priority` to pick the
	// strongest match deterministically:
	//   1 = OWNER from companies.owner_firebase_uid
	//   2 = role from company_users (active rows only)
	//
	// The difference is ONLY in how the result is interpreted below: here any
	// match means the user belongs to the company.
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
		// No match in either source — the user does NOT belong to the company.
		return false, "", "", nil
	} else if err != nil {
		return false, "", "", fmt.Errorf("failed to validate company membership: %v", err)
	}

	role = strings.ToUpper(strings.TrimSpace(role))
	email = strings.TrimSpace(email)

	// Any match at all means the user belongs to the company. Role is returned
	// only for context; it does NOT gate access here.
	return true, role, email, nil
}
