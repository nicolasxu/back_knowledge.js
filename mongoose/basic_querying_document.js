// query method is done on the model, no need for the instance of model 
var source = "http://mongoosejs.com/docs/models.html";


// find, findById, findOne, or where

// 1. find
Tank.find({ size: 'small' }).where('createdDate').gt(oneYearAgo).exec(callback);

// 2. remove
Tank.remove({ size: 'large' }, function (err) {
  if (err) return handleError(err);
  // removed!
});

// 3. update
// http://mongoosejs.com/docs/api.html#model_Model.findOneAndUpdate
var query = { name: 'borne' };
Model.findOneAndUpdate(query, { $set: { name: 'jason borne' }}, options, callback)
