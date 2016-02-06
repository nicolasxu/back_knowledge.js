function salt_password() {
	// npm install bcryptjs --save
	var bcrypt = require('bcryptjs');
	// advantage:
	//  1. salt is a part of the password,
	//  2. doesn’t need compilation
	bcrypt.hash('thePassword911', 8, function(err, hash) {
		// ... Store the hash, which is a password and salt together
	});



	// Compare password
	var hasFromDb; // load the has password from db
	bcypt.compare("thePassword911", hasFromDb, function(err, res){
		// res === true, or
		// res === false
	});
}