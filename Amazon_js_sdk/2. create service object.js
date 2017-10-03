"create an javascrip object in order to use aws api"
/* 

To access service features through the JavaScript API, you first 
create a service object through which you access a set of features 
provided by the underlying client class.

*/


var dynamodb = new AWS.DynamoDB({apiVersion: '2012-08-10'});

// or

var ec2 = new AWS.EC2({region: 'us-west-2', apiVersion: '2014-10-01'});
