var source = "http://expressjs.com/en/4x/api.html";

function (req, res, next) {
	res.sendStatus(200); // equivalent to res.status(200).send('OK')
	res.sendStatus(403); // equivalent to res.status(403).send('Forbidden')
	res.sendStatus(404); // equivalent to res.status(404).send('Not Found')
	res.sendStatus(500); // equivalent to res.status(500).send('Internal Server Error')

	res.status(403).end();
	res.status(400).send('Bad Request');
	res.status(404).sendFile('/absolute/path/to/404.png');

	
	res.status(200).json({code: 4001, message: "weak password"});
}