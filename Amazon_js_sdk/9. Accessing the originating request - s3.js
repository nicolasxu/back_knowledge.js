s3.getObject({Bucket: 'bucket', Key: 'key'}).on('success', function(response) {
   console.log("Key was", response.request.params.Key);
}).send();

// http://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/the-response-object.html
