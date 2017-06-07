var Hapi = require('hapi');
var uuid = require('uuid');
var nJwt = require('njwt');

var secret = 'LoremIpsumDolorSitAmet';
let PORT = 3773;

var claims = {
 "sub": "1234567890",
 "id": "2",
 "name": "John Adams",
 "admin": true,
 "jti": "b92d9136-47e2-42b7-b754-5b77843470ba",
 "iat": 1496856145,
 "exp": 1496859745
}

var jwt = nJwt.create(claims, secret,"HS256");
var token = jwt.compact();

var validate = function (decoded, request, callback) {
  const users = {
    1: {
      name: 'George Washington'
    },
    2: {
      name: 'John Adams'
    },
    2: {
      name: 'Thomas Jefferson'
    }
  };

  console.log('validate', decoded);
  if (!users[decoded.id]) {
    return callback(null, false);
  }
  else {
    return callback(null, true);
  }
};


let navigationHtml = `
<ul>
<li><a href=/>public:/</a></li>
<li><a href=/token>public:/token</a></li>
<li><a href=/secret>/secret</a></li>
<li><a href=/restricted>/restricted</a></li>
</ul>
`

var server = new Hapi.Server();
server.connection({ port: PORT });
        // include our module here ↓↓
server.register(require('hapi-auth-jwt2'), function (err) {

  if(err){
    console.log(err);
  }

  server.auth.strategy(
    'jwt',
    'jwt',
    {
      key: secret, // 'NeverShareYourSecret',
      validateFunc: validate,
      verifyOptions: {
        algorithms: [ 'HS256' ]
      }
    });

  server.auth.default('jwt');

  server.route([
    {
      method: 'POST', path: '/user/login', config: { auth: false },
      handler: function(request, reply) {
        reply(token);
      }
    },
    {
      method: 'GET', path: '/', config: { auth: false },
      handler: function(request, reply) {
        reply(navigationHtml);
      }
    },

    {
      method: 'GET', path: '/token', config: { auth: false },
      handler: function(request, reply) {
        reply({
          url: `http://localhost:3773/secret?token=${token}`
        });
      }
    },

    {
      method: 'GET', path: '/secret', config: { auth: 'jwt' },
      handler: function(request, reply) {
        reply({
          text: 'Token used for /secret'
        })
          .header('Authorization', request.headers.authorization);
      }
    },

    {
      method: 'GET', path: '/restricted', config: { auth: 'jwt' },
      handler: function(request, reply) {
        reply({text: 'Token used for /restricted'})
          .header('Authorization', request.headers.authorization);
      }
    }
  ]);
});

server.start(function () {
  console.log('Server running at:', server.info.uri);
});
