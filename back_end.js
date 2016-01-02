
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
					
				}
			}




		}
		function full_projection() {
			var source = "https://docs.mongodb.org/manual/reference/operator/projection/";
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