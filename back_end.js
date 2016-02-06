
function backEnd() {


	function nodejs() {
		function parse_command_line() {
			var source = "http://stackoverflow.com/questions/4351521/how-to-pass-command-line-arguments-to-node-js";
			// The arguments are stored in process.argv
			
			// or you can use 
			// yargs: https://www.npmjs.com/package/yargs
			// to parse the param for you
		}

		function npm_caret_tilde_star() {
			// * download the latest version
			// ^ match major release: ^1.2.3 will match 1.x.x, 1.3.0, but not 2.0.0
			// ~ match most recent minor version: ~1.2.3 will match 1.2.x, e.g. 1.2.4, but not 1.3.0
		}

		function use_redis_as_session_store() {
			// 1. make sure redis is installed
			// 2. make sure express is install
			// 3. npm install "connect-redis express-session --save
			// 4. ater use cookieParser midware
			app.use(session({ // var session = require('express-session');
				resave: true,
				saveUninitialized: true,
				store: new RedisStore({ // var RedisStore = require('connect-redis')(session);
					host: 'localhost',
					port: 6379
				}),
				secret: '0FFD9D8D-78F1-4A30-9A4E-0940ADE81645',
				cookie: { path: '/', maxAge: 3600000 }
				}));			
		}

		function logic_to_check_authentication() {
			// Logic to check if user is authenticated 
			// in the session in req object
			// to check if login, for example:
			app.use(function(req, res, next) {
				if (req.session && req.session.authenticated) {
					return next();
				} else {
					return res.redirect('/login');
				}
			});
		}

		function logic_to_login_user() {

			app.post('/login', function(req, res) {
			// Check the database for the username and password combination
			// In a real-world scenario you would salt the password
				db.findOne({username: req.body.username,
										password: req.body.password},
					function(error, user) {
						if (error) {
							return next();
						}
						if (!user) {
							return next(new Error('Bad username/password'));
						}
						req.session.user = user;
						res.redirect ('/protected_area');
					}
				);
			});
		}

		function oAuth_logic() {
			// OAuth 1.0/2.0 requires callback routes for the user redirect back to our sites.
			// TBD
		}
		function security_tips() {
			// CSRF explanation and example: 
			// https://www.youtube.com/watch?v=oSvl1cdF4UM
			// solutions:
			// 1. use csurf nodejs middleware 
			// 2. re-authenticate user for each important POST request
			
			// The csrf must be preceded by cookie-parser and express-session
			// npm install csurf --save
			var csrf = require('csurf');
			app.use(function (request, response, next) {
				response.locals.csrftoken = request.csrfToken();
				next();
			});
		}

		function bad_idea_to_run_nodejs_as_root() {
			var key = "Process Permission";
			// it’s possible to drop privileges after binding to a port.
			// The idea here is
			// that we pass the values of GID (group ID) and UID (user ID) to the Node.js app and use the
			// parsed values to set the group identity and user identity of the process.
			
			/*
				Doesn't work on windows. use process.platform to check platform
			*/

			// ... Importing modules
			var app = express();
				// ... Configurations, middleware and routes
				http.createServer(app).listen(app.get('port'), function(){
				console.log("Express server listening on port "
				+ app.get('port'));
				process.setgid(parseInt(process.env.GID, 10));
				process.setuid(parseInt(process.env.UID, 10));
			});	
		}

		function check_OS_in_nodejs() {
			// process.platform
		}

		function security_headers() {
			// npm install helmet --save
			
			var helmet = require('helmet');
			// apply the middleware before the routes
			app.use(helmet());
			// it add 9 things in the HTTP header
			/*
				1. crossdomain:
				2. csp:
				3. hidePoweredBy:
				4. hsts:
				5. ienoopen:
				6. nocache:
				7. nosniff:
				8. xframe:
				9. xssFilter:
			*/
		}

		function apply_middleware() {
			// app.use() from Express.js to apply middleware
			// Normally you should apply all middleware before routes
			
			// Instantiate the Express.js app
			app.use(function(req, res, next) {
				console.log('%s %s — %s', (new Date).toString(), req.method, req.url);
				return next();
			});
			// Implement server routes
		}
		function apply_middleware_for_specific_path() {
			// On the other hand, if we want to prefix the middleware, 
			// a.k.a. mounting, we can use the
			// path parameter, which restricts the use of this particular 
			// middleware to only the routes that
			// have such a prefix.
			// Instantiate the Express.js app
			app.use('/admin', function(req, res, next) {
				console.log('%s %s — %s', (new Date).toString(), req.method, req.url);
				return next();
			});
			// Actually implement the /admin route
		}

		function essential_middlewares() {
			// 1. serve-static
			//    Static middleware enables pass-through requests for static assets.
			app.use('/css', express.static(__dirname + '/public/css'));
			app.use('/img', express.static(__dirname + '/public/images'));
			app.use('/js', express.static(__dirname + '/public/javascripts'));
			// Express.js 4.x provides only one middleware function out of the
			// box: express.static().
			
			// 2. compression
			//    npm install compression --save
						// compression middleware is usually placed at the very beginning of an Express.js app
						// configuration, so that it precedes the other middleware
			  var compression = require('compression');
				// ... Typical Express.js set up...
				app.use(compression());
		}

		function essential_middlewares2() {
			// 1. morgan
			//   npm install morgan --save
			//   it is a logger
			var logger = require('morgan');
			// ... Configurations
			app.use(logger('common')); // log common 
			app.use(logger('dev'));	// log dev
			app.use(logger(':method :url :status :res[content-length] - :response-timems')); // log customized 

			// 2. body-parser
			// npm install body-parser --save
			// Most important, for parsing HTML body payload
				var bodyParser = require('body-parser');
				// config
				app.use(bodyParser.json());  // application/json
				app.use(bodyParser.urlencoded({ extended: false })); // xww-form-urlencoded
				// bodyParser.raw();
				// bodyParser.text();
				
				// It decides which parser to use by the MIME type of 
				// application/json in Request header.
				// The result will be put in the req.body object and pass on to next middleware
				
				// body-parser module’s urlencoded() middleware parses only requests with the 
				// xww-form-urlencoded header 
		}
		function essential_middlewares3() {
			// formidable
			// cookie-parser
			// express-session
			// csurf
			// express.static()
			
			// 1. connect-timeout
			// npm install connect-timeout --save
			// Use of this middleware is recommended only on specific 
			// routes (e.g., '/slowroute')
				var timeout = require('connect-timeout');
				// ... Instantiation and configuration
				app.get(
					'/slow-request',
					timeout('1s'),
					function(request, response, next) {
						setTimeout(function(){
							if (request.timedout) return false;
							return next();
						}, 999 + Math.round(Math.random()));
						}, function(request, response, next) {
							response.send('ok');
						}
				);

				// 2. errorshandler, especially useful in development
				// npm install errorhandler --save
				// usage:
				var errorHandler = require('errorhandler');
				// ... Configurations
				app.use(errorHandler());

				// This error handler is triggered from inside of the other middleware by calling next()
				// with an error object; for example, 
				next(new Error('something went wrong')) 
				// If we
				// call next() without arguments, Express.js assumes that there were no errors and proceeds to
				// the next middleware in the chain.
		}
		function essential_middlewares4() {
			// 1. method-overwirde
			// npm install method-override --save
			// Patch browsers that only support GET and POST in 
			// HTML form. 
			
			// The method-override module can use the 
			// X-HTTP-Method-Override=VERB header
			// from the incoming requests, e.g.:
			var methodOverride = require('method-override');
			// ... Configuratoins
			app.use(methodOverride('X-HTTP-Method-Override'));

			// or you can use query string 
			var methodOverride = require('method-override');
			// ... Configuratoins
			app.use(methodOverride('_method'));

			// this way to trigger overide method:
			app.delete('/purchase-orders', function(request, response){
				console.log('The DELETE route has been triggered');
				response.status(204).end();
			});
			// curl http://localhost:3000/purchase-orders/?_method=DELETE -X POST
			// output => The DELETE route has been triggered
			
			// 2. response-time 
			// npm install response-time --save
			// It adds X-Response-Time to HTTP header
			var responseTime = require('response-time');
			// ... Middleware
			app.use(responseTime(4)); // 4 is for 4 digits after decimal, e.g.: 514.3982
			// it contains the time in milli seconds from the request starts
			// to the request ends
		}
		function essential_middlewares5() {
			// 1. serve-favicon
				// npm install serve-favicon --save
				var favicon = require('serve-favicon');
				// ... Instantiations
				app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
				// path: The path to the favorite icon file, or Buffer with the icon data (Buffer is a Node.js
				//   binary type)
				// options: maxAge in milliseconds—how long to cache the favorite icon; the default is 1
				// day
			// 2. serve-index
			// npm install serve-index --save
			var serveIndex = require('serve-index');
			// ... Middleware
			app.use('/shared', serveIndex(
				path.join('public','shared'),
				{'icons': true}
			));
			app.use(express.static('public'));
		}
		function essential_middlewares6() {
			// 1. vhost
			// npm install vhost --save
			// for enables you to use a different routing logic based on the domain
			// e.g.: two Express.js apps, one for api and the other for web
				var app = express()
				var api = express()
				var web = express()
				// ... Configurations, middleware and routes
				app.use(vhost('www.hackhall.com', web))
				app.use(vhost('api.hackhall.com', api))
					// domain: String or RegExp; for example, *.webapplog.com
					// server: Server object (express or connect); for example, api or web
				app.listen(3000)

			// 2. connect-busboy (use node-formidable, it has better document)
			//   npm install connect-busboy --save
			//   The busboy form parser basically takes the
			//   incoming HTTP(S) request multipart body and allows us to use its fields, uploaded files, and
			//   so forth.

				var busboy = require('connect-busboy');
				// ... Configurations
				app.use('/upload', busboy({immediate: true })); 
				// trigger the middleware to start parsing file only for this /upload route

				app.use('/upload', function(request, response) {
					request.busboy.on('file', function(fieldname, file, filename, encoding, mimetype) {
						// then busboy is available in the request object,
						// we listen to busboy event
						file.on('data', function(data){
							fs.writeFile('upload' + fieldname + filename, data);
						});
						file.on('end', function(){
							console.log('File' + filename + 'is ended');
						});
					});

					request.busboy.on('finish', function(){
						console.log('Busboy is finished');
						response.status(201).end();
					})
				});
		}
		function essential_middlewares7() {
			// cookies and kegrip: Alternatives to cookieparser
			// (https://www.npmjs.org/package/cookies,
			// https://www.npmjs.org/package/keygrip,
			// https://www.npmjs.org/package/cookie-parser)
			// cookie-session: Cookie-based session store
			// (https://www.npmjs.org/package/cookie-session)
			// raw-body: For requests as buffers (https://www.npmjs.org/package/raw-body)
			// connect-multiparty: Uses mutliparty and acts as an alternative to connectbusboy
			// (https://www.npmjs.org/package/connect-multiparty,
			// https://www.npmjs.org/package/multiparty,
			// https://www.npmjs.org/package/connect-busboy)
			// qs: Alternative to query and querystring (https://www.npmjs.org/package/qs,
			// https://www.nodejs.org/api/querystring.html)
			// st, connect-static, and static-cache: Caching of static assets
			// (https://www.npmjs.org/package/st,
			// https://www.npmjs.org/package/connect-static, and
			// https://www.npmjs.org/package/static-cache)
			// express-validator: Incoming data validation/sanitation
			// (https://www.npmjs.org/package/express-validator)
			// everyauth and passport: Authentication and authorization middleware
			// (https://www.npmjs.org/package/everyauth and
			// https://www.npmjs.org/package/passport)
			// oauth2-server: OAuth2 server middleware
			// (https://www.npmjs.org/package/oauth2-server)
			// helmet: Collection of security middleware
			// (https://www.npmjs.org/package/helmet)
			// connect-cors: Cross-origin resource sharing (CORS) support for Express.js servers
			// (https://www.npmjs.org/package/connect-cors)
			// connect-redis: Redis session store for Express.js sessions
			// (https://www.npmjs.org/package/connect-redis)
		}
		function multipart() {
			// In older versions, bodyParser.multipart() middleware is known to be prone to
			// malfunctioning when handling large file uploads.
			// Instead, the Express.js team
			// recommends using busboy, formidable, or multiparty. 
			// 
			// https://github.com/felixge/node-formidable
			// is much better choice
		}

		function mongoose() {
			
		}
	}

	function mongoDB(){
		// 1. Install MongoDB: https://docs.mongodb.org/manual/tutorial/install-mongodb-on-os-x/
		// 2. Start mongoDB
		// 		mongod
		// 3. open mongoDB shell environment(just a V8 javascript command line interpreter)
		//    mongo
		// 4. you can also use robomongo on Mac to access mongo DB
		function basic_command() {
			/*
			1. show dbs
			2. use <db_name>
				 MongoDB will only create this database when you insert first data
			3. use demo // switch to demo db
			4. db // show current db
			5. show collections // show collections in current selected DB
			6. db.user.insert({"name":"nicolas", "password": "123456"}) 
					// create collection called "user" in selected db, and 
					// generate 1st document(record) by insert command
			7. db.user.find() // find document in user collection of current db
			                  // no selection criteria, so return everything, but
			                  // just show first 20 by default
			8. native mongoDB collection is schema less, so you can insert documents with
			   different keys into the same collection. 
		 */
		}

		function basic_CRUD() {
			function read() {
				// below command works in mongo shell
				// 1. db.users.find({age:{$gt:18}}).sort({age:1})
				// 2. 
					db.users.find(         // collection
						{age:{$gt:18}}, 	   // query criteria
						{name:1, address:1}  // projection
					).limit(5)             // cursor modifier
				// 3. SQL to MongoDB Mapping Chart
				//    https://docs.mongodb.org/manual/reference/sql-comparison/
			}
		}

		function full_query_operators() {
			function comparsion() {
				function $eq() {
					// { <field>: { $eq: <value> } }
					// short: { field: <value> }
					// <value> is a document, the order of the fields in the document matters
					// <value> is an array, the array should match exactly, or the <field> contains an element that matches the array exactly
					// 
					/* collection example: 
						{ _id: 1, item: { name: "ab", code: "123" }, qty: 15, tags: [ "A", "B", "C" ] }
						{ _id: 2, item: { name: "cd", code: "123" }, qty: 20, tags: [ "B" ] }
						{ _id: 3, item: { name: "ij", code: "456" }, qty: 25, tags: [ "A", "B" ] }
						{ _id: 4, item: { name: "xy", code: "456" }, qty: 30, tags: [ "B", "A" ] }
						{ _id: 5, item: { name: "mn", code: "000" }, qty: 20, tags: [ [ "A", "B" ], "C" ] }
					*/
					// 1. value === value
					db.inventory.find( { qty: { $eq: 20 } } ) 
					// same as:
					db.inventory.find( { qty: 20 } )

					// 2. obj.value === value
					db.inventory.find( { "item.name": { $eq: "ab" } } )
					// same as:
					db.inventory.find( { "item.name": "ab" } )

					// 3. array === value
					db.inventory.find( { tags: { $eq: "B" } } )
					// same
					db.inventory.find( { tags: "B" } )
					// match documents if value is one one of the array items
					
					// 4. array === array
					db.inventory.find( { tags: { $eq: [ "A", "B" ] } } )
					// same as
					db.inventory.find( { tags: [ "A", "B" ] } )
					// match field where array exactly same as target array
					// or field contains element match exactly target array
					// the above query matches =>
					// { _id: 3, item: { name: "ij", code: "456" }, qty: 25, tags: [ "A", "B" ] }
					// { _id: 5, item: { name: "mn", code: "000" }, qty: 20, tags: [ [ "A", "B" ], "C" ] }
					
						/******** Important ***********/
					 // The order of the items matters, and should be exactly the same as target array, e.g.:
					 // ["A", "B"] will not match ["B", "A"]
					 
					 // 5. value === array
					 // alway not be equal, will not match any thing. 
				}

				function $in() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/in/#op._S_in";
					// { field: { $in: [<value1>, <value2>, ... <valueN> ] } }
					// value of a field equals any value in the specified array
					
					// 1. value $in array
					db.inventory.find( { qty: { $in: [ 5, 15 ] } } )
					// 2. array $in array
					// { _id: 1, item: "abc", qty: 10, tags: [ "school", "clothing" ], sale: false }

					db.inventory.update(
	                     { tags: { $in: ["appliances", "school"] } },
	                     { $set: { sale:true } }
	                   )
					// set the sale field value to true where the tags field holds an array 
					// with at least one element matching either "appliances" or "school".
					
					// 3. value $in regex
					db.inventory.find( { tags: { $in: [ /^be/, /^st/ ] } } )
					// This query selects all documents in the inventory collection where the 
					// tags field holds an array that contains at least one element that 
					// starts with either be or st.
				}
				function $gt() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/gt/#op._S_gt";

					// 1. value $gt value
					db.inventory.find( { qty: { $gt: 20 } } )

					// 2. obj.value $gt value
					db.inventory.update( { "carrier.fee": { $gt: 2 } }, { $set: { price: 9.99 } } )
					// Important: it only updates the first match document!!!
					
					// if you want to update all:
					db.inventory.update(
					  { "carrier.fee": { $gt: 2 } },
					  { $set: { price: 9.99 } },
					  { multi: true } // to enable update all match document
					)
				}
				function $gte() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/gte/#op._S_gte";

					// 1. value $gte value
					db.inventory.find( { qty: { $gte: 20 } } )
					// 2. obj.value $gte value
					db.inventory.update( { "carrier.fee": { $gte: 2 } }, { $set: { price: 9.99 } } )
				}
				function $lt() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/lt/#op._S_lt";

					// 1. value $lt value
					db.inventory.find( { qty: { $lt: 20 } } )
					// 2. obj.value $lt value
					db.inventory.update( { "carrier.fee": { $lt: 20 } }, { $set: { price: 9.99 } } )
					// Important!! it only update the first match!
				}
				function $lte() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/lte/#op._S_lte";

					// 1. value $lte value
					db.inventory.find( { qty: { $lte: 20 } } )
					// 2. obj.value $lte value
					db.inventory.update( { "carrier.fee": { $lte: 5 } }, { $set: { price: 9.99 } } )
					// Important! It only update the first occurrence. 
				}
				function $ne() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/ne/#op._S_ne";
					// 1. value $ne value
					db.inventory.find( { qty: { $ne: 20 } } )
					// 2. obj.value $ne value
					db.inventory.update( { "carrier.state": { $ne: "NY" } }, { $set: { qty: 20 } } )
					// Update carrier whose state field value does not equal “NY”, or not exist
				}
				function $nin() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/nin/#op._S_nin";

					// $nin selects the documents where:
					// - the field value is not in the specified array or
					// - the field does not exist.

					// 1. value $nin array
					db.inventory.find( { qty: { $nin: [ 5, 15 ] } } )
					// it is neither 5 nor 15, nothing match any item in the array
					
					// 2. array $nin array
					db.inventory.update( { tags: { $nin: [ "appliances", "school" ] } }, { $set: { sale: false } } )
					// query documents that none of the array item matches any item in the target array
					// e.g.: none of the tag in tags matches neither "appliances" nor "school"
				}
			}

			function logical() {
				function $or() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/or/#op._S_or";
					// { $or: [ { <expression1> }, { <expression2> }, ... , { <expressionN> } ] }
					
					db.inventory.find( { $or: [ { quantity: { $lt: 20 } }, { price: 10 } ] } )
					// It will perform full collection or index scan. You can add index to speed it up by.
					db.inventory.createIndex( { quantity: 1 } )
					db.inventory.createIndex( { price: 1 } )

					// 2. exception
					//  -  $or cannot contain a near clause with any other clause (near clause includes $nearSphere and $near) 
					
					// 3. $or vs $in
					// If you want to check equality of the same field, use $in, e.g.:
					db.inventory.find ( { quantity: { $in: [20, 50] } } )
				}
				function $and() {
					// $and performs a logical AND operation on an array of two or more expressions
					// If the first expression (e.g. <expression1>) evaluates to false, 
					// MongoDB will not evaluate the remaining expressions
					db.inventory.find( { $and: [ { price: { $ne: 1.99 } }, { price: { $exists: true } } ] } )
					// same as
					db.inventory.find( { price: { $ne: 1.99, $exists: true } } )

					// example 2:
					db.inventory.find( {
					  $and : [
				      { $or : [ { price : 0.99 }, { price : 1.99 } ] },
			        { $or : [ { sale : true }, { qty : { $lt : 20 } } ] }
					  ]
					})
				}
				function $not() {
					db.inventory.find( { price: { $not: { $gt: 1.99 } } } )
					// example:
					// - the price field value is less than or equal to 1.99 or
					// - the price field does not exist
					
					// { $not: { $gt: 1.99 } } is different from the $lte operator. { $lte: 1.99 } returns only the
					// documents where price field exists and its value is less than or equal to 1.99.

					// basic rule:
					// - $not only affects other operators
					// - $ne operator to test the contents of fields directly
					
					// Important!
					// 1. $not on array may product unexpected result
					// 2. $not cannot use with $regex operator, instead, use "//", e.g.:
					db.inventory.find( { item: { $not: /^p.*/ } } )
				}
				function $nor() {
					db.inventory.find( { $nor: [ { price: 1.99 }, { sale: true } ]  } )
						// select both false, or not exist
						/*

							- contain the price field whose value is not equal to 1.99 and contain the sale field whose value is not equal to true or
							- contain the price field whose value is not equal to 1.99 but do not contain the sale field or
							- do not contain the price field but contain the sale field whose value is not equal to true or
							- do not contain the price field and do not contain the sale field						

						*/
					// $nor and $exists
					db.inventory.find( { $nor: [ { price: 1.99 }, { price: { $exists: false } },
                             { sale: true }, { sale: { $exists: false } } ] } )

					// contain the price field whose value is not equal to 1.99 and 
					// contain the sale field whose value is not equal to true
				}
			}

			function element() {
				function $exists() {

				}
				function $type() {
					db.inventory.find( { qty: { $exists: true, $nin: [ 5, 15 ] } } )
					// check key exists or not. The value can be null.
				}
			}

			function evaluation() {
				function $mod() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/mod/#op._S_mod";
					/*
					{ "_id" : 1, "item" : "abc123", "qty" : 0 }
					{ "_id" : 2, "item" : "xyz123", "qty" : 5 }
					{ "_id" : 3, "item" : "ijk123", "qty" : 12 }

					*/


					db.inventory.find( { qty: { $mod: [ 4, 0 ] } } )
					// => db.inventory.find( { qty: { $mod: [ 4, 0 ] } } )

					// if the [] has fewer than 2 element or more than 2 element, 
					// an error is thrown. 
				}

				function $regex() {
					// { <field>: /pattern/<options> }
					// { name: { $in: [ /^acme/i, /^ack/ ] } }
					// IMPORTANT
					// You cannot use $regex operator expressions inside an $in.
					
					// { "_id" : 100, "sku" : "abc123", "description" : "Single line description." }
					// { "_id" : 101, "sku" : "abc789", "description" : "First line\nSecond line" } 
					db.products.find( { description: { $regex: /^S/, $options: 'm' } } )
				}

				function $text() {
					// $text performs a text search on the content of the fields 
					// !!!!!!!!!!!! indexed with a text index  !!!!!!!!!!!!!
					// here is how to create text index
					db.reviews.createIndex( { comments: "text" } )
					/*
					{
					  $text:
					    {
					      $search: <string>,
					      $language: <string>,
					      $caseSensitive: <boolean>,
					      $diacriticSensitive: <boolean>
					    }
					}
					*/
					
					// example: 
					db.articles.insert(
					   [
					     { _id: 1, subject: "coffee", author: "xyz", views: 50 },
					     { _id: 2, subject: "Coffee Shopping", author: "efg", views: 5 },
					     { _id: 3, subject: "Baking a cake", author: "abc", views: 90  },
					     { _id: 4, subject: "baking", author: "xyz", views: 100 },
					     { _id: 5, subject: "Café Con Leche", author: "abc", views: 200 },
					     { _id: 6, subject: "Сырники", author: "jkl", views: 80 },
					     { _id: 7, subject: "coffee and cream", author: "efg", views: 10 },
					     { _id: 8, subject: "Cafe con Leche", author: "xyz", views: 10 }
					   ]
					)

					// 1. basic search
					db.articles.find( { $text: { $search: "coffee" } } )
					// 2. logic or on terms
					db.articles.find( { $text: { $search: "bake coffee cake" } } )
					// 3. search for a phrase
					db.articles.find( { $text: { $search: "\"coffee shop\"" } } )
					// 4. exclude a term 
					db.articles.find( { $text: { $search: "coffee -shop" } } )
					// 5. search different language
					db.articles.find(
					  { $text: { $search: "leche", $language: "es" } }
					)
					// 6. Case and Diacritic Insensitive Search
					db.articles.find( { $text: { $search: "сы́рники CAFÉS" } } )
					// 7. Case Sensitive Search
					db.articles.find( { $text: { $search: "Coffee", $caseSensitive: true } } )
					// 8. Case Sensitive Search for a Phrase
					db.articles.find( {
					  $text: { $search: "\"Café Con Leche\"", $caseSensitive: true }
					})
					// 9. Case Sensitivity with Negated Term
					db.articles.find( { $text: { $search: "Coffee -shop", $caseSensitive: true } } )
					// 10. Diacritic Sensitive Search
					db.articles.find( { $text: { $search: "CAFÉ", $diacriticSensitive: true } } )
					// 11. Diacritic Sensitivity with Negated Term
					db.articles.find(
					  { $text: { $search: "leches -cafés", $diacriticSensitive: true } }
					)
					// 12. Return the Text Search Score
					db.articles.find(
					  { $text: { $search: "cake" } },
					  { score: { $meta: "textScore" } }
					)
					// 13. Sort by Text Search Score
					db.articles.find(
					  { $text: { $search: "coffee" } },
					  { score: { $meta: "textScore" } }
					).sort( { score: { $meta: "textScore" } } )
					// 14. return top 2 matching documents
					db.articles.find(
					  { $text: { $search: "coffee" } },
					  { score: { $meta: "textScore" } }
					).sort( { score: { $meta: "textScore" } } ).limit(2)

					// Text Search with Additional Query and Sort Expressions
					db.articles.find(
					  { author: "xyz", $text: { $search: "coffee bake" } },
					  { score: { $meta: "textScore" } }
					).sort( { date: 1, score: { $meta: "textScore" } } )
				}
				function $where() {
					// In general, you should use $where only when you 
					// can’t express your query using another operator.
					db.myCollection.find( { $where: "this.credits == this.debits" } );
					db.myCollection.find( { $where: "obj.credits == obj.debits" } );

					// this or obj refers to current document
					
					db.myCollection.find( "this.credits == this.debits || this.credits > this.debits" );
					db.myCollection.find( function() { return (this.credits == this.debits || this.credits > this.debits ) } );
					// if the query consists only of the $where operator, 
					// you can pass in just the JavaScript expression or JavaScript functions
				}
			}
			function geospatial() {
				// checkout the geoJSON spec:
				var url =  "http://geojson.org/geojson-spec.html";
				function $geoWithin() {
					db.places.find(
					   {
					     loc: {
					       $geoWithin: {
					          $geometry: {
					             type : "Polygon" ,
					             coordinates: [ [ [ 0, 0 ], [ 3, 6 ], [ 6, 1 ], [ 0, 0 ] ] ]
					          }
					       }
					     }
					   }
					)

					db.places.find(
					   {
					     loc: {
					       $geoWithin: {
					          $geometry: {
					             type : "Polygon" ,
					             coordinates: [
					               [
					                 [ -100, 60 ], [ -100, 0 ], [ -100, -60 ], [ 100, -60 ], [ 100, 60 ], [ -100, 60 ]
					               ]
					             ],
					             crs: {
					                type: "name",
					                properties: { name: "urn:x-mongodb:crs:strictwinding:EPSG:4326" }
					             }
					          }
					       }
					     }
					   }
					)
					// $within is deprecated
				}

				function $geoIntersects() {
					db.places.find(
					   {
					     loc: {
					       $geoIntersects: {
					          $geometry: {
					             type: "Polygon" ,
					             coordinates: [
					               [ [ 0, 0 ], [ 3, 6 ], [ 6, 1 ], [ 0, 0 ] ]
					             ]
					          }
					       }
					     }
					   }
					)

					db.places.find(
					   {
					     loc: {
					       $geoIntersects: {
					          $geometry: {
					             type : "Polygon",
					             coordinates: [
					               [
					                 [ -100, 60 ], [ -100, 0 ], [ -100, -60 ], [ 100, -60 ], [ 100, 60 ], [ -100, 60 ]
					               ]
					             ],
					             crs: {
					                type: "name",
					                properties: { name: "urn:x-mongodb:crs:strictwinding:EPSG:4326" }
					             }
					          }
					       }
					     }
					   }
					)
				}

				function $near() {

					db.places.find(
					   {
					     location:
					       { $near :
					          {
					            $geometry: { type: "Point",  coordinates: [ -73.9667, 40.78 ] },
					            $minDistance: 1000,
					            $maxDistance: 5000
					          }
					       }
					   }
					)

					db.legacy2d.find(
					   { location : { $near : [ -73.9667, 40.78 ], $maxDistance: 0.10 } }
					)					
				}
				function $nearSphere() {
					// $nearSphere requires a geospatial index:


					db.places.find(
					   {
					     location: {
					        $nearSphere: {
					           $geometry: {
					              type : "Point",
					              coordinates : [ -73.9667, 40.78 ]
					           },
					           $minDistance: 1000,
					           $maxDistance: 5000
					        }
					     }
					   }
					)

					db.legacyPlaces.find(
					  { location : { $nearSphere : [ -73.9667, 40.78 ], $maxDistance: 0.10 } }
					)
				}
			}

			function array() {
				function $all() {
					var source = "https://docs.mongodb.org/manual/reference/operator/query/all/#op._S_all";
					//  array that contains all the specified elements
					
					var searchObj = { tags: { $all: [ "ssl" , "security" ] } };
					// same as
					var equalObj = { $and: [ { tags: "ssl" }, { tags: "security" } ] }; 

						/*
						When passed an array of a nested array (e.g. [ [ "A" ] ] ), 
						$all can now match documents where the field contains the 
						nested array as an element (e.g. field: [ [ "A" ], ... ]), 
						or the field equals the nested array (e.g. field: [ "A" ]).
						 */
						db.articles.find( { tags: { $all: [ [ "ssl", "security" ] ] } } )
						db.articles.find( { $and: [ { tags: [ "ssl", "security" ] } ] } )
						db.articles.find( { tags: [ "ssl", "security" ] } )

						// As such, the $all expression can match documents where the
						//  tags field is an array that contains the nested array 
						//  [ "ssl", "security" ] or is an array that equals the nested 
						//  array:
						tags: [ [ "ssl", "security" ], [] ]
						tags: [ "ssl", "security" ]
				}
				function $elemMatch() {
					// matches documents that contain an 
					// array field with at least one element that
					//  matches all the specified query criteria.
					/*
					{ _id: 1, results: [ 82, 85, 88 ] }
					{ _id: 2, results: [ 75, 88, 89 ] }
					 */
					
					db.scores.find(
					  { results: { $elemMatch: { $gte: 80, $lt: 85 } } }
					)

					db.survey.find(
					   { results: { $elemMatch: { product: "xyz", score: { $gte: 8 } } } }
					)

					db.survey.find(
				   { "results.product": "xyz" }
					)
				}
				function $size() {
					db.collection.find( { field: { $size: 2 } } );
					// Important:
					// 						$size does not accept ranges of values. 
					// Workaround:
					//To select documents based on fields with different 
					//numbers of elements, create a counter field that 
					//you increment when you add elements to a field.
				}
			}

			function projection() {
				function $() {
					var source = "https://docs.mongodb.org/manual/reference/operator/projection/positional/#proj._S_";

					/*
					example:
					{ "_id" : 1, "semester" : 1, "grades" : [ 70, 87, 90 ] }
					{ "_id" : 2, "semester" : 1, "grades" : [ 90, 88, 92 ] }
					{ "_id" : 3, "semester" : 1, "grades" : [ 85, 100, 90 ] }
					{ "_id" : 4, "semester" : 2, "grades" : [ 79, 85, 80 ] }
					{ "_id" : 5, "semester" : 2, "grades" : [ 88, 88, 92 ] }
					{ "_id" : 6, "semester" : 2, "grades" : [ 95, 90, 96 ] }
										 */
					
					db.students.find( { semester: 1, grades: { $gte: 85 } },
                  { "grades.$": 1 } )
					// =>
					/*
					{ "_id" : 1, "grades" : [ 87 ] }
					{ "_id" : 2, "grades" : [ 90 ] }
					{ "_id" : 3, "grades" : [ 85 ] }
					 */
					
					// another example:
					/*
					
						{ "_id" : 7, semester: 3, "grades" : [ { grade: 80, mean: 75, std: 8 },
						                                       { grade: 85, mean: 90, std: 5 },
						                                       { grade: 90, mean: 85, std: 3 } ] }

						{ "_id" : 8, semester: 3, "grades" : [ { grade: 92, mean: 88, std: 8 },
						                                       { grade: 78, mean: 90, std: 5 },
						                                       { grade: 88, mean: 85, std: 3 } ] }

					 */
					db.students.find(
					   { "grades.mean": { $gt: 70 } },
					   { "grades.$": 1 }
					) // result =>
					// { "_id" : 7, "grades" : [  {  "grade" : 80,  "mean" : 75,  "std" : 8 } ] }
					// { "_id" : 8, "grades" : [  {  "grade" : 92,  "mean" : 88,  "std" : 8 } ] }
				}
				function $elemMatch() {
					var source = "https://docs.mongodb.org/manual/reference/operator/projection/elemMatch/#proj._S_elemMatch";
					// Both the $ operator and the $elemMatch operator project a subset of elements from an array based on a condition.
					// The $elemMatch projection operator takes an explicit 
					// condition argument. This allows you to project based on a condition not in the query, or if you need to project based on multiple fields in the array’s embedded documents.
				}
				function $meta() {
					var source = "https://docs.mongodb.org/manual/reference/operator/projection/meta/#proj._S_meta";

						db.collection.find(
						   {/* query object*/},
						   { score: { $meta: "textScore" } }
						).sort( { score: { $meta: "textScore" } } )
				}
				function $slice() {
					var source = "https://docs.mongodb.org/manual/reference/operator/projection/slice/#proj._S_slice";
					db.posts.find( {}, { comments: { $slice: 5 } } )
					// only return first 5 items in comments array
					db.posts.find( {}, { comments: { $slice: -5 } } )
					// return last 5 in comments
					db.posts.find( {}, { comments: { $slice: [ 20, 10 ] } } )
					// [ skip , limit ]
					db.posts.find( {}, { comments: { $slice: [ -20, 10 ] } } )
					// This operation returns 10 items as well, beginning with the item that is 20th from the last item of the array.


				}
			}
		}

		function update_operators() {
			function field() {
				function $inc() {
					// - The $inc operator accepts positive and negative values.
					// - If the field does not exist, $inc creates the field and sets the field to the specified value.
					// - Use of the $inc operator on a field with a null value will generate an error.
					// - $inc is an atomic operation within a single document.				
					/*
					{
					  _id: 1,
					  sku: "abc123",
					  quantity: 10,
					  metrics: {
					    orders: 2,
					    ratings: 3.5
					  }
					}
					 */
					db.products.update(
					   { sku: "abc123" },
					   { $inc: { quantity: -2, "metrics.orders": 1 } }
					)
				}
				function $mul() {
					// Multiply the value of a field by a number. 
					// { _id: 1, item: "ABC", price: 10.99 }

					db.products.update(
					   { _id: 1 },
					   { $mul: { price: 1.25 } }
					)
				}
				function $rename() {
					var source ="https://docs.mongodb.org/manual/reference/operator/update/rename/#up._S_rename";
					// The $rename operator updates the name of a field
					
					db.students.update( { _id: 1 }, { $rename: { "nmae": "name" } } )

					db.students.update( { _id: 1 }, { $rename: { "name.first": "name.fname" } } )

					db.students.update( { _id: 1 }, { $rename: { 'wife': 'spouse' } } )
				}
				function $setOnInsert() {
					/*
						If an update operation with upsert: true results in an 
						insert of a document, then $setOnInsert assigns the specified 
						values to the fields in the document. If the update operation 
						does not result in an insert, $setOnInsert does nothing.
					*/
					db.products.update(
					  { _id: 1 },
					  {
					     $set: { item: "apple" },
					     $setOnInsert: { defaultQty: 100 }
					  },
					  { upsert: true }
					)
				}
				function $set() {
					var source = "https://docs.mongodb.org/manual/reference/operator/update/set/#up._S_set";
					// The $set operator replaces the value of a field with the specified value.

					// If the field does not exist, $set will add a new field with the specified value,
					//  provided that the new field does not violate a type constraint.
					

					db.products.update(
				    { _id: 100 },
				    { $set:
				      {
				        quantity: 500,
				        details: { model: "14Q3", make: "xyz" },
				        tags: [ "coats", "outerwear", "clothing" ]
				      }
				    }
					)  

					db.products.update(
					  { _id: 100 },
					  { $set: { "details.make": "zzz" } }
					)

					db.products.update(
					  { _id: 100 },
					  { $set:
					    {
					      "tags.1": "rain gear",
					      "ratings.0.rating": 2
					    }
					  }
					)
				}
				function $unset() {
					// The $unset operator deletes a particular field.
					// If the field does not exist, then $unset does nothing (i.e. no operation).
					db.products.update(
					   { sku: "unknown" },
					   { $unset: { quantity: "", instock: "" } }
					)
				}
				function $min() {
					// The $min updates the value of the field to a specified 
					// value if the specified value is less than the current value of the field.
					
					// { _id: 1, highScore: 800, lowScore: 200 }
					db.scores.update( { _id: 1 }, { $min: { lowScore: 150 } } )
					// result => 
					// { _id: 1, highScore: 800, lowScore: 150 }
				}
				function $max() {
					//  The $max operator updates 
					//  the value of the field to a specified value if the specified value is greater than the current value of the field. 
					//  { _id: 1, highScore: 800, lowScore: 200 }

					db.scores.update( { _id: 1 }, { $max: { highScore: 950 } } )

					// {
					//    _id: 1,
					//    desc: "decorative arts",
					//    dateEntered: ISODate("2013-10-01T05:00:00Z"),
					//    dateExpired: ISODate("2013-10-01T16:38:16.163Z")
					// }

					db.tags.update(
					   { _id: 1 },
					   { $max: { dateExpired: new Date("2013-09-30") } }
					)
				}
				function $currentDate() {
					//  The $currentDate operator sets the value of 
					//  a field to the current date, either as a Date or a timestamp.
					
					// { _id: 1, status: "a", lastModified: ISODate("2013-10-02T01:11:18.965Z") }
					
					// - a boolean true to set the field value to the 
					//    current date as a Date, or
					// - a document { $type: "timestamp" } or { $type: "date" } 
					//   which explicitly specifies the type. The operator is 
					//   case-sensitive and accepts only the lowercase "timestamp" 
					//   or the lowercase "date".
					
					// { _id: 1, status: "a", lastModified: ISODate("2013-10-02T01:11:18.965Z") }

					db.users.update(
					   { _id: 1 },
					   {
					     $currentDate: {
					        lastModified: true,
					        "cancellation.date": { $type: "timestamp" }
					     },
					     $set: {
					        status: "D",
					        "cancellation.reason": "user request"
					     }
					   }
					) // result =>

					var result = {
					   "_id" : 1,
					   "status" : "D",
					   "lastModified" : ISODate("2014-09-17T23:25:56.314Z"),
					   "cancellation" : {
					      "date" : Timestamp(1410996356, 1),
					      "reason" : "user request"
					   }
					}
				}
			}
			function array() {
				function $() {
					// 1st in the matched array
					
					// - the positional $ operator acts as a placeholder for the first element that matches the query document, and
					// - the array field must appear as part of the query document.
					
					/*
						{ "_id" : 1, "grades" : [ 80, 85, 90 ] }
						{ "_id" : 2, "grades" : [ 88, 90, 92 ] }
						{ "_id" : 3, "grades" : [ 85, 100, 90 ] }
					*/
					db.students.update(
					   { _id: 1, grades: 80 },
					   { $set: { "grades.$" : 82 } }
					) // update first 80 in grades to 82

					// example 2:
					/*
					{
						  _id: 4,
						  grades: [
						     { grade: 80, mean: 75, std: 8 },
						     { grade: 85, mean: 90, std: 5 },
						     { grade: 90, mean: 85, std: 3 }
						  ]
						}
					 */
					db.students.update(
					   { _id: 4, "grades.grade": 85 },
					   { $set: { "grades.$.std" : 6 } }
					)
				}

				function $addToSet() {
					// The $addToSet operator adds a value to an
					//  array unless the value is already present, 
					//  in which case $addToSet does nothing to that array.
					
					// { _id: 1, letters: ["a", "b"] }
					db.test.update(
					   { _id: 1 },
					   { $addToSet: {letters: [ "c", "d" ] } }
					) // result => 
					// { _id: 1, letters: [ "a", "b", [ "c", "d" ] ] }
					// To add each element of the value separately, use 
					// the $each modifier with $addToSet.
					

					// another example: 
					// { _id: 2, item: "cable", tags: [ "electronics", "supplies" ] }
 					db.inventory.update(
					   { _id: 2 },
					   { $addToSet: { tags: { $each: [ "camera", "electronics", "accessories" ] } } }
					) // result => 

					// {
					// 	_id: 2,
					// 	item: "cable",
					// 	tags: [ "electronics", "supplies", "camera", "accessories" ]
					// }
				}
				function $pop(){
					// The $pop operator removes the first or last element of an array.
					// { _id: 1, scores: [ 8, 9, 10 ] }
					db.students.update( { _id: 1 }, { $pop: { scores: -1 } } ) // remove first
					// result =>
					// { _id: 1, scores: [ 9, 10 ] }
					// 
					db.students.update( { _id: 1 }, { $pop: { scores: 1 } } )
					// remove the last element in the array
				}
				function $pullAll() {
					// The $pullAll operator removes all instances of the specified values from an existing array.
					// { _id: 1, scores: [ 0, 2, 5, 5, 1, 0 ] }
					db.survey.update( { _id: 1 }, { $pullAll: { scores: [ 0, 5 ] } } )
					// result =>
					// { "_id" : 1, "scores" : [ 2, 1 ] }
				}
				function $pull() {
					var source = "https://docs.mongodb.org/manual/reference/operator/update/pull/#pull-array-of-documents";
					// 1. === specific value
					db.stores.update(
					    { },
					    { $pull: { fruits: { $in: [ "apples", "oranges" ] }, vegetables: "carrots" } },
					    { multi: true }
					)
					// 2. match condition
					db.profiles.update( { _id: 1 }, { $pull: { votes: { $gte: 6 } } } )
					// 3. remove items from an array of documents
					db.survey.update(
					  { },
					  { $pull: { results: { score: 8 , item: "B" } } },
					  { multi: true }
					)
					// 4. $elemMatch, please review the official document
					//    on the above link
					db.survey.update(
					  { },
					  { $pull: { results: { answers: { $elemMatch: { q: 2, a: { $gte: 8 } } } } } },
					  { multi: true }
					)
				}
				function $push() {
					// The $push operator appends a specified value to an array.
					
					// - If the field is not an array, the operation will fail.
					// - If the field is absent in the document to update, 
					//    $push adds the array field with the value as its element.
					// - If the value is an array, $push appends the whole array as a single element. 

					// you can use $each modifier to the $push operator
					// $each, $slice, $sort, $position
					// example: 
					db.students.update(
					   { name: "joe" },
					   { $push: { scores: { $each: [ 90, 92, 85 ] } } }
					)
					// example: 
					db.students.update(
					   { _id: 5 },
					   {
					     $push: {
					       quizzes: {
					          $each: [ { wk: 5, score: 8 }, { wk: 6, score: 7 }, { wk: 7, score: 6 } ],
					          $sort: { score: -1 },
					          $slice: 3
					       }
					     }
					   }
					)
				}
			}

			function modifiers() {
				function $each() {
					db.students.update(
					   { name: "joe" },
					   { $push: { scores: { $each: [ 90, 92, 85 ] } } }
					)

					db.inventory.update(
				    { _id: 2 },
				    { $addToSet: { tags: { $each: [ "camera", "electronics", "accessories" ] } } }
				  )
				}

				function $slice() {

					db.students.update(
					   { _id: 1 },
					   {
					     $push: {
					       scores: {
					         $each: [ 80, 78, 86 ],
					         $slice: -5
					       }
					     }
					   }
					)

					db.students.update(
					   { _id: 5 },
					   {
					     $push: {
					       quizzes: {
					          $each: [ { wk: 5, score: 8 }, { wk: 6, score: 7 }, { wk: 7, score: 6 } ],
					          $sort: { score: -1 },
					          $slice: 3
					       }
					     }
					   }
					)
				}

				function $sort() {
					db.students.update(
					   { _id: 1 },
					   {
					     $push: {
					       quizzes: {
					         $each: [ { id: 3, score: 8 }, { id: 4, score: 7 }, { id: 5, score: 6 } ],
					         $sort: { score: 1 }
					       }
					     }
					   }
					)
				}

				function $position() {
					var source = "https://docs.mongodb.org/manual/reference/operator/update/position/#up._S_position";
					// The $position modifier specifies the location 
					// in the array at which the $push operator insert elements.
					
					db.students.update(
					   { _id: 1 },
					   {
					     $push: {
					        scores: {
					           $each: [ 50, 60, 70 ],
					           $position: 0
					        }
					     }
					   }
					)

					db.students.update(
					   { _id: 1 },
					   {
					     $push: {
					        scores: {
					           $each: [ 20, 30 ],
					           $position: 2
					        }
					     }
					   }
					)
				}
			}

			function isolation() {
				function $isolated() {
					db.foo.update(
					  { status : "A" , $isolated : 1 },
					  { $inc : { count : 1 } },
					  { multi: true }
					)
					// Without the $isolated operator, the multi-update 
					// operation will allow other operations to interleave with its update of the matched documents.
				}
			}
		}

		function aggregation_pipeline_operators() {
			function $project() {
				var source = "https://docs.mongodb.org/manual/reference/operator/aggregation/project/#pipe._S_project";
				/*
				{
				  "_id" : 1,
				  title: "abc123",
				  isbn: "0001122223334",
				  author: { last: "zzz", first: "aaa" },
				  copies: 5
				}
				 */
				db.books.aggregate( [ { $project : { title : 1 , author : 1 } } ] )
				// => { "_id" : 1, "title" : "abc123", "author" : { "last" : "zzz", "first" : "aaa" } }
				db.books.aggregate( [ { $project : { _id: 0, title : 1 , author : 1 } } ] )
				// => { "title" : "abc123", "author" : { "last" : "zzz", "first" : "aaa" } }
				db.bookmarks.aggregate( [ { $project: { "stop.title": 1 } } ] )

				// 2. Include Computed Fields
				/*
				{
				  "_id" : 1,
				  title: "abc123",
				  isbn: "0001122223334",
				  author: { last: "zzz", first: "aaa" },
				  copies: 5
				}
				*/
				db.books.aggregate(
				   [
				      {
				         $project: {
				            title: 1,
				            isbn: {
				               prefix: { $substr: [ "$isbn", 0, 3 ] },
				               group: { $substr: [ "$isbn", 3, 2 ] },
				               publisher: { $substr: [ "$isbn", 5, 4 ] },
				               title: { $substr: [ "$isbn", 9, 3 ] },
				               checkDigit: { $substr: [ "$isbn", 12, 1] }
				            },
				            lastName: "$author.last",
				            copiesSold: "$copies"
				         }
				      }
				   ]
				) // =>
				// {
				//    "_id" : 1,
				//    "title" : "abc123",
				//    "isbn" : {
				//       "prefix" : "000",
				//       "group" : "11",
				//       "publisher" : "2222",
				//       "title" : "333",
				//       "checkDigit" : "4"
				//    },
				//    "lastName" : "zzz",
				//    "copiesSold" : 5
				// }

				// 3. Project New Array Fields
				// { "_id" : ObjectId("55ad167f320c6be244eb3b95"), "x" : 1, "y" : 1 }
				db.collection.aggregate( [ { $project: { myArray: [ "$x", "$y" ] } } ] )
				// => { "_id" : ObjectId("55ad167f320c6be244eb3b95"), "myArray" : [ 1, 1 ] }
				db.collection.aggregate( [ { $project: { myArray: [ "$x", "$y", "$someField" ] } } ] )
				// =>{ "_id" : ObjectId("55ad167f320c6be244eb3b95"), "myArray" : [ 1, 1, null ] }
			}
			function $match() {
				/*
				{ "_id" : ObjectId("512bc95fe835e68f199c8686"), "author" : "dave", "score" : 80, "views" : 100 }
				{ "_id" : ObjectId("512bc962e835e68f199c8687"), "author" : "dave", "score" : 85, "views" : 521 }
				{ "_id" : ObjectId("55f5a192d4bede9ac365b257"), "author" : "ahn", "score" : 60, "views" : 1000 }
				{ "_id" : ObjectId("55f5a192d4bede9ac365b258"), "author" : "li", "score" : 55, "views" : 5000 }
				{ "_id" : ObjectId("55f5a1d3d4bede9ac365b259"), "author" : "annT", "score" : 60, "views" : 50 }
				{ "_id" : ObjectId("55f5a1d3d4bede9ac365b25a"), "author" : "li", "score" : 94, "views" : 999 }
				{ "_id" : ObjectId("55f5a1d3d4bede9ac365b25b"), "author" : "ty", "score" : 95, "views" : 1000 }
				*/
				
				db.articles.aggregate(
				    [ { $match : { author : "dave" } } ]
				);

				db.articles.aggregate( [
				  { $match: { $or: [ { score: { $gt: 70, $lt: 90 } }, { views: { $gte: 1000 } } ] } },
				  { $group: { _id: null, count: { $sum: 1 } } }
				]);
				// => 
				// { "_id" : null, "count" : 5 }

			}
		}
	

	}

	function redis() {
		function get_session_by_id() {
		
			/*
				> get sess:A3l_jSr25tbWWjRHot9sEUM5OApCn21R
			*/
			// in redis install directory, type:
			// src/redis-cli to start redis command line
			
			// to get session dat associate with this session ID
			// result example: =>
				// 		"{\"cookie\":{\"originalMaxAge\":3600000,\"expires\":\"2014-09-
				// 03T19:03:55.007Z\",\"httpOnly\":true,\"path\":\"/\"},\"counter\":1}"
		}

		function get_list_of_session_keys() {
			/*
				> keys sess*
			*/
		}
	}

	function operation_system() {

		function linux_ls_find_by_file_name() {
			/*
				ls abc*   # list all files starting with abc---
				ls *abc*  # list all files containing --abc--
				ls *abc   # list all files ending with --abc
			*/
		}

	}






}