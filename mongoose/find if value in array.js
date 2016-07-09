var source = "http://stackoverflow.com/questions/18148166/find-document-with-array-that-contains-a-specific-value";

var PersonSchema = new Schema ({
    name : String,
    favouriteFoods : [String]
});

var Person = mongoose.model('Person', PersonSchema);


Person.find({ favouriteFoods: { "$in" : ["sushi"]} }, ...);
