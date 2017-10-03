var s3 = new AWS.S3({apiVersion: '2006-03-01'});
var params = {Bucket: 'myBucket', Key: 'myImageFile.jpg'};
var file = require('fs').createWriteStream('/path/to/file.jpg');
s3.getObject(params).createReadStream().pipe(file);


// http://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/requests-using-stream-objects.html
