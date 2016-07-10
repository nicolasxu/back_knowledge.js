var source = "http://stackoverflow.com/questions/13850819/can-i-determine-if-a-string-is-a-mongodb-objectid";


var idString = "537eed02ed345b2e039652d2";
var oid = new ObjectId('537eed02ed345b2e039652d2') //537eed02ed345b2e039652d2

if(oid.toString() === idString) {
	// good id
} else {
	// bad id
}


// method 2

if (id.match(/^[0-9a-fA-F]{24}$/)) {
    // it's an ObjectID    
} else {
    // nope    
}