var Hapi = require('hapi');
var uuid = require('uuid');
var nJwt = require('njwt');
var sodium = require('sodium').api;

var md5 = require('md5');
var hash = new Buffer(sodium.crypto_pwhash_STRBYTES);


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

const makeUsers = () => {
  let users = [
    {
      name: 'George Washington',
      email: 'gw@us.gov',
      password: 'gw'
    },
    {
      name: 'John Adams',
      email: 'ja@us.gov',
      password: 'ja'
    },
    {
      name: 'Thomas Jefferson',
      email: 'tj@us.gov',
      password: 'tj'
    }
  ];
  users.map(user => {
    var salt = Math.random();

    let base = `${salt}:${user.password}`;
    var passwordBuffer = new Buffer(base);
    hash = sodium.crypto_pwhash_str(
      passwordBuffer,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
    );

    let md5Hash = md5(base);
    let result =  {};
    result[user.email] = {
      name: user.name,
      email: user.email,
      salt: salt,
      hash: md5Hash // hash.toString()
    };

    console.log(result);

    return result;

  })
}
// makeUsers()

const login = (email, password) =>  {
  let users = {
    'gw@us.gov':
    { id: 1,
      name: 'George Washington',
      email: 'gw@us.gov',
      salt: 0.3825882128395248,
      hash: '517df48ab807f998d8823738a6f68697'
    },
    'ja@us.gov':
    {
      id: 2,
      name: 'John Adams',
      email: 'ja@us.gov',
      salt: 0.24036750186029487,
      hash: '9a14748feaa34f03456b7defdaa30f63'
    },
    'tj@us.gov':
    {
      id: 3,
      name: 'Thomas Jefferson',
      email: 'tj@us.gov',
      salt: 0.44261049781007067,
      hash: '16e02d3528da10b84075587a6179669a'
    }
  };

  let user = users[email];
  let base = `${user.salt}:${password}`;
  if (user.hash === md5(base)) {
    console.log(user.name, 'logged in');
    return user
  }
}

var report = {
        "Data": 39329392,
        "Name": "labore",
        "Chart": {
                "category": [
                        "ea"
                ],
                "series": [
                        69058461,
                        -68137048,
                        1911288
                ]
        },
        "User": {
                "id": -12821672,
                "username": "est",
                "firstName": "irure",
                "lastName": "ut",
                "email": "nostrud eiusmod et",
                "password": "occaecat adipisicing ut culpa nulla",
                "phone": "est pariatur Excepteur anim consectetur",
                "userStatus": -29400731
        },
        "ApiResponse": {
                "code": -37480749,
                "type": "ullamco",
                "message": "elit ea"
        }
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
<li><a href=/login>public:/login</a></li>
<li><a href=/logout>public:/logout</a></li>
<li><a href=/token>public:/token</a></li>
<hr/>
<li><a href=/secret>/secret</a></li>
<li><a href=/restricted>/restricted</a></li>
<hr/>
<li><a href=/secret?token=${token}/secret>authenticated:/secret</a><tt>?token=${token}</tt></li>
</ul>
<pre>
<script>
document.write(localStorage.getItem('jw-jwt'))
</script>
</pre>
`;

let loginHtml = `
<h1>Sign In</h1>
<div class="container">
  <div class="card card-container">
    <img id="profile-img" class="profile-img-card" src="https://ssl.gstatic.com/accounts/ui/avatar_2x.png" />
    <p id="profile-name" class="profile-name-card"></p>
    <form class="form-signin" action="/user/login" method="POST">
      <span id="reauth-email" class="reauth-email"></span>
      <input type="email" value="gw@us.gov" id="inputEmail" class="form-control" placeholder="Email address" required autofocus>
      <input type="password" value="gw" id="inputPassword" class="form-control" placeholder="Password" required>
      <div id="remember" class="checkbox">
        <label>
          <input type="checkbox" value="remember-me"> Remember me
        </label>
      </div>
      <button class="btn btn-lg btn-primary btn-block btn-signin" type="submit">Sign in</button>
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
      key: secret, // 'NeverShareYourSecret',
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

        let email = request.payload.email || 'gw@us.gov';
        let password = request.payload.password || 'gw';
        let user = login(email, password);

        var claims = {
          "sub": "1234567890",
          "id": user.id,
          "name": user.name,
          "email": user.email,
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
