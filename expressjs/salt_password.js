function salt_password() {
	// npm install bcryptjs --save
	var bcrypt = require('bcryptjs');
	// advantage:
	//  1. salt is a part of the password,
	//  2. doesn’t need compilation
	bcrypt.hash('pr0expressr0cks!', 8, function(err, hash) {
	// ... Store the hash, which is a password and salt together
	});
}