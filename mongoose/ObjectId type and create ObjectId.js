var source = "http://stackoverflow.com/questions/8111846/how-to-set-objectid-as-a-data-type-in-mongoose"

// no need to create any uuid in each document, since _id field MUST exist for all standard documents

// ObjectId type example: 
var mongoose = require('mongoose');

var Schema = mongoose.Schema,
    ObjectId = Schema.ObjectId;
var Schema_Product = new Schema({
    categoryId  : ObjectId, // a product references a category _id with type ObjectId
    title       : String,
    price       : Number
});


// Create Object Id object

var mongoose = require('mongoose');
var id = mongoose.Types.ObjectId(); // Generate new Id
var oldId = mongoose.Types.ObjectId('577d7e9fbb1e9967c60fbaf5');
// id is a newly generated ObjectId.

