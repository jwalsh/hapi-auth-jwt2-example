const Hapi = require('hapi');
const uuid = require('uuid');
const nJwt = require('njwt');
const sodium = require('sodium').api;
const _ = require('lodash');
const md5 = require('md5');
const corsHeaders = require('hapi-cors-headers')

let hash = new Buffer(sodium.crypto_pwhash_STRBYTES);

const secret = 'LoremIpsumDolorSitAmet';
const PORT = 3773;

// A mock user to populate the form
let sample = {};

// Create a mock users table
const makeUsers = () => {

  const users = `Jason	Walsh	j@wal.sh
Test	User	kewlphantomhawk
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
        const u = e.split('	');
        return {
          id: i,
          name: `${u[0]} ${u[1]}`,
          username: u[2],
          password: 'password'
        }
      });
  sample = _.sample(users)
  const result = users.map(user => {
    const salt = Math.random();

    const base = `${salt}:${user.password}`;
    const passwordBuffer = new Buffer(base);
    hash = sodium.crypto_pwhash_str(
      passwordBuffer,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
    );

    const md5Hash = md5(base);
    const result = {
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

const users = makeUsers();


console.log('Users', Object.keys(users))

const login = (username, password) =>  {

  const user = users[username];
  console.log('login()', username, password, user)
  const base = `${user.salt}:${password}`;
  if (user.hash === md5(base)) {
    console.log(user.name, 'logged in');
    return user
  } else {
    console.log('Username and password invalid', user.hash, md5(base));
    return null; //
  }
}

const validate = function (decoded, request, callback) {
  console.log('validate', decoded);
  if (!users[decoded.username]) {
    return callback(null, false);
  }
  else {
    return callback(null, true);
  }
};


const navigationJs = () => {
  function parseJwt (token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace('-', '+').replace('_', '/');
    return JSON.parse(window.atob(base64));
  };
  const token = localStorage.getItem('jw-jwt');
  if (token) {
    console.log(parseJwt(token));
    document.write(JSON.stringify(parseJwt(token), null, '  '));
  }
}

// console.log(navigationJs.toString())
const headerHtml = `
<a href=/>[home]</a><br/><hr/>
`;

const footerHtml = `
<pre>
<script>
(${navigationJs.toString()})()
</script>
</pre>
`
const navigationHtml = `
${headerHtml}
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
${footerHtml}
`;

const loginHtml = `
${headerHtml}
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
${footerHtml}
`;


const logoutHtml = `
${headerHtml}
<h1>You have been logged out.</h1>
<script>
localStorage.removeItem('jw-jwt');
</script>
${footerHtml}
`;




const server = new Hapi.Server();
server.ext('onPreResponse', corsHeaders);


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

        const username = request.payload.username || request.payload.username;
        const password = request.payload.password;
        console.log(username, password)
        const user = login(username, password);
        if (!user) {
          console.log('No user found')
          reply(new Error('401'));
        } else {

          const claims = {
            "sub": "1234567890",
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "admin": true,
            "jti": "b92d9136-47e2-42b7-b754-5b77843470ba",
            "iat": 1496856145,
            "exp": 1496859745
          }

          const jwt = nJwt.create(claims, secret,"HS256");
          const token = jwt.compact();
          reply(`${headerHtml}<h1>Logged in ${user.name}</h1><script>localStorage.setItem('jw-jwt', '${token}');</script>${footerHtml}`);
        }
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
