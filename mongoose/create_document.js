// documents are instance of model


var Tank = mongoose.model('Tank', yourSchema);

var small = new Tank({ size: 'small' });
small.save(function (err) {
  if (err) return handleError(err);
  // saved!
})

// or


Tank.create({ size: 'small' }, function (err, small) {
  if (err) return handleError(err);
  // saved!
}) 

// make sure connection to mongoDB is create

// mongoose.connect('localhost', 'gettingstarted');

