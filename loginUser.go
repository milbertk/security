package security

func LoginUser(token string) (exception bool, exist string, err error) {

	_, err = ValidateFirebaseToken(token)

	if err != nil {

		return false, "Error in validation of token", err
	}

	//if token its ok, insert into tracking table, this part must be translated to an api place

	//create locat JWT

	//return local JWT

	return true, "true", nil

}
