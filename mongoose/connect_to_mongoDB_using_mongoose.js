var source = "http://mongoosejs.com/docs/api.html";
var mongoose = require('mongoose');

mongoose.connect('localhost', 'gettingstarted');

// or 
mongoose.connect('mongodb://user:pass@localhost:port/database');

// or 
var uri = 'mongodb://hostA:27501,hostB:27501';
var opts = { mongos: true };
mongoose.connect(uri, opts);

// or 
var uri = 'mongodb://nonexistent.domain:27000';
mongoose.connect(uri, function(error) {
  // if error is truthy, the initial connection failed.
})