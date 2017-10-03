s3.listObjects({Bucket: 'bucket'}).on('success', function handlePage(response) {
    // do something with response.data
    if (response.hasNextPage()) {
        response.nextPage().on('success', handlePage).send();
    }
}).send();

// http://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/the-response-object.html
