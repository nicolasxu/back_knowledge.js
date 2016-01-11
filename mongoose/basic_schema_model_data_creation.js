// the logic of mongoose is:
//   1. use new Schema({}) to create a schema
//   2. use mongoose.model('ModelName', schema) to create Model
//   3. use new Model to create model from schema for saving or updating data



var mongoose = require('mongoose');
var Schema = mongoose.Schema;
// 1. create schema

var blogSchema = new Schema({
  title:  String,
  author: String,
  body:   String,
  comments: [{ body: String, date: Date }],
  date: { type: Date, default: Date.now },
  hidden: Boolean,
  meta: {
    votes: Number,
    favs:  Number
  }
});

// 2. create model 
var Blog = mongoose.model('Blog', blogSchema);

// 3. create instance of model
var blog = new Blog({ title: 'How to improve yourself' });

// 4. save data
blog.save(function(err){
	if(err) {
		return handleError(err);
	}
});
