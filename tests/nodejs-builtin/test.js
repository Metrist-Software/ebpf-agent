const https = require('https');

const options = {
  hostname: 'www.google.com',
  port: 443,
  path: '/',
  method: 'GET',
};

https.request(options, res => {
  console.log(`statusCode: ${res.statusCode}`);
}).end();
