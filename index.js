var Hapi = require('hapi');
var uuid = require('uuid');
var nJwt = require('njwt');
var sodium = require('sodium').api;
var _ = require('lodash');

var md5 = require('md5');
var hash = new Buffer(sodium.crypto_pwhash_STRBYTES);


var secret = 'LoremIpsumDolorSitAmet';
let PORT = 3773;

let sample = {};

const makeUsers = () => {

let users = `Jason	Walsh	j@wal.sh
George	Washington	gw@us.gov
Karen	Cornish	karen.cornish@foo.com
Bernadette	Sharp	bernadette.sharp@foo.com
Carol	Ince	carol.ince@foo.com
Deirdre	Baker	deirdre.baker@foo.com
Jennifer	Wilkins	jennifer.wilkins@foo.com
Vanessa	Chapman	vanessa.chapman@foo.com
Adam	Sutherland	adam.sutherland@foo.com
David	Payne	david.payne@foo.com
Stephanie	Parsons	stephanie.parsons@foo.com
Matt	Bell	matt.bell@bar.com
Keith	Lawrence	keith.lawrence@bar.com
Matt	Fisher	matt.fisher@bar.com
Megan	Howard	megan.howard@bar.com
Andrea	Lyman	andrea.lyman@bar.com
Dominic	Graham	dominic.graham@bar.com
Sally	Ross	sally.ross@bar.com
Katherine	Kerr	katherine.kerr@bar.com
Diane	Ogden	diane.ogden@bar.com
Melanie	Quinn	melanie.quinn@bar.com
Ruth	Cameron	ruth.cameron@bar.com
James	Ferguson	james.ferguson@bar.com
Lucas	Peake	lucas.peake@bar.com`
    .split('\n')
    .map((e, i) => {
      let u = e.split('	');
      return {
        id: i,
        name: `${u[0]} ${u[1]}`,
        username: u[2],
        password: 'password'
      }
    });
  sample = _.sample(users)
  let result = users.map(user => {
    var salt = Math.random();

    let base = `${salt}:${user.password}`;
    var passwordBuffer = new Buffer(base);
    hash = sodium.crypto_pwhash_str(
      passwordBuffer,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
    );

    let md5Hash = md5(base);
    let result = {
      name: user.name,
      username: user.username,
      // password: user.password, // debugging
      salt: salt,
      hash: md5Hash // hash.toString()
    };
    return result;
  })
    .reduce((p, c) => {
      p[c.username] = c;
      return p;
    }, {});

  return result;
};

let users = makeUsers();


console.log('Users', Object.keys(users))

const login = (username, password) =>  {

  let user = users[username];
  console.log('login()', username, password, user)
  let base = `${user.salt}:${password}`;
  if (user.hash === md5(base)) {
    console.log(user.name, 'logged in');
    return user
  }
}

var validate = function (decoded, request, callback) {
  console.log('validate', decoded);
  if (!users[decoded.username]) {
    return callback(null, false);
  }
  else {
    return callback(null, true);
  }
};


let navigationHtml = `
<ul>
<li><a href=/>public:/</a></li>
<li><a href=/login>public:/login</a></li>
<li><a href=/logout>public:/logout</a></li>
<li><a href=/token>public:/token</a></li>
<hr/>
<li><a href=/secret>/secret</a></li>
<li><a href=/restricted>/restricted</a></li>
<hr/>
<li>JWT: <a href=/secret?token=LOREM/secret>authenticated:/secret</a></li>
</ul>
<pre>
<script>
function parseJwt (token) {
            var base64Url = token.split('.')[1];
            var base64 = base64Url.replace('-', '+').replace('_', '/');
            return JSON.parse(window.atob(base64));
        };
var token = localStorage.getItem('jw-jwt');
if (token) {
console.log(parseJwt(token));
document.write(JSON.stringify(parseJwt(token), null, '  ');
}
</script>
</pre>
`;

let loginHtml = `
<h1>Sign In</h1>
<div class="container">
  <div class="card card-conteimg" class="profile-img-card" src="https://ssl.gstatic.com/accounts/ui/avatar_2x.png" />
    <p id="profile-name" class="profile-name-card"></p>
    <form class="form-signin" action="/user/login" method="POST">
      <span id="reauth-username" class="reauth-username"></span>
      <input type="email" value="${sample.username}" name="username" class="form-control" placeholder="Username or Email" required autofocus>
      <input type="password" value="${sample.password}" name="password" class="form-control" placeholder="Password" required>
      <div id="remember" class="checkbox">
        <label>
          <input type="checkbox" value="remember-me"> Remember me
        </label>
      </div>
      <input class="btn btn-lg btn-primary btn-block btn-signin" type="submit">Sign in</input>
    </form><!-- /form -->
    <a href="#" class="forgot-password">
      Forgot the password?
    </a>
  </div><!-- /card-container -->
</div><!-- /container -->
`;


let logoutHtml = `
<h1>You have been logged out.</h1>
`;




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
      key: secret,
      validateFunc: validate,
      verifyOptions: {
        algorithms: [ 'HS256' ]
      }
    });

  server.auth.default('jwt');

  server.route([
    {
      method: 'POST',
      path: '/user/login',
      config: { auth: false },
      handler: function(request, reply) {
        console.log('POST: /user/login', request.payload);

        let username = request.payload.username || request.payload.username;
        let password = request.payload.password;
        console.log(username, password)
        let user = login(username, password);

        var claims = {
          "sub": "1234567890",
          "id": user.id,
          "name": user.name,
          "username": user.username,
          "admin": true,
          "jti": "b92d9136-47e2-42b7-b754-5b77843470ba",
          "iat": 1496856145,
          "exp": 1496859745
        }

        var jwt = nJwt.create(claims, secret,"HS256");
        var token = jwt.compact();
        reply(`<h1>Logged in ${user.name}</h1><script>localStorage.setItem('jw-jwt', '${token}');</script>`);
      }
    },

    {
      method: 'GET', path: '/', config: { auth: false },
      handler: function(request, reply) {
        reply(navigationHtml);
      }
    },

    {
      method: 'GET', path: '/login', config: { auth: false },
      handler: function(request, reply) {
        reply(loginHtml);
      }
    },

    {
      method: 'GET', path: '/logout', config: { auth: false },
      handler: function(request, reply) {
        reply(logoutHtml);
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
