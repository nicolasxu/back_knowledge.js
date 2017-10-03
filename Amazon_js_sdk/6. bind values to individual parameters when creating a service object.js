/* 

In addition, you can bind values to individual parameters when 
creating a service object using the params parameter.

*/


var s3bucket = new AWS.S3({params: {Bucket: 'myBucket'}, apiVersion: '2006-03-01' });

/* 


By binding the service object to a bucket, the s3bucket service object treats the 
myBucket parameter value as a default value that no longer needs to be specified 
for subsequent operations. 

*/

var s3bucket = new AWS.S3({ params: {Bucket: 'myBucket'}, apiVersion: '2006-03-01' });
s3bucket.getObject({Key: 'keyName'});
// ...
s3bucket.getObject({Bucket: 'myOtherBucket', Key: 'keyOtherName'});