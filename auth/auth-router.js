const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

const Users = require('../users/users-model.js');

//
// when we register, all we do is take the username
// and password, hash the password (with salt, of course!),
// and store them in the DB, and return success.
//
// these will be used in any /login request to validate
// the login attempt.
//
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});


//
// when a /login occurs, the browser app must pass the username
// and password in the body.
//
// here, we validate the password guess against the database.
//
// if the login attempt is successful, we generate a JWT and
// send it back to the browser. 
//
// The browser app will save the token, and should know to send 
// it in an Authorization header in any future API calls to 
// "restricted" API endpoints (where authentication is required).
//
// This prevents the user from having to enter their credentials
// every time an API call is made, and prevents the browser app
// from needing to cache the username/password so it can send it
// in headers every time an API call is made. The browser app just
// sends the token instead.
//
// username/password is long-lasting... if they ever get out,
// they can be exploited for a long time without being detected.
//
// but JWT's have a much shorter lifespan... they are set to expire.
// So they are much more secure for the browser app to use.
//
// remember that the JWT consists of a header, a payload, and a
// signature. The header describes how the signature was generated.
// The payload contains information that the API server/service
// (or other related services) might need to do its job. Typically,
// the payload consists of "claims" about the "subject" - properties,
// permissions, etc.
//
// Because the JWT is *not encrypted*, NEVER store anything sensitive 
// in a JWT!!! It is essentially plain text (though encoded ... but the
// encoding is not secure at all!)
router.post('/login', (req, res) => {
  // get the username and password from the body.
  let { username, password } = req.body;

  // look up the user. We are using the promise .then.catch syntax...
  // remember that findBy() returns an array... we use .first() to 
  // get the one user we want (if there are any users, there will only
  // be one user... the username column has a "unique" constraint in the DB.)
  Users.findBy({ username })
    .first()
    .then(user => {
      // when the search returns, check to see if there is a user, and if so,
      // compare the user's password hash from the DB with the password
      // that was sent in the req.body. bcrypt.compareSync() will synchronously
      // generate a hash of the password guess and compare with the user.password
      // hash.
      if (user && bcrypt.compareSync(password, user.password)) {

        // if we have gotten this far, it means that the username/password is
        // valid. So now, we make a JWT. See the genToken() method below.
        const token = genToken(user);
        
        // add the token to the response body. The browser app will need to
        // parse the token out of the body and save it somehow, so it can
        // use it in future API requests.
        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token
        });

      } else {
        // if the user doesn't exist, or the password doesn't hash 
        // correctly, ... NO SOUP FOR YOU.
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    // this is for DB lookup errors...
    .catch(error => {
      res.status(500).json(error);
    });
});

//
// this is a method for generating a JWT using the jsonwebtoken
// module.
//
// Remember to NEVER store sentisitve information in the payload...
// it is not encrypted! It is merely Base64-encoded.
//
// The secret is pulled from a config file, which either gets it 
// from .env, the operating environment, or uses a default secret.
function genToken(user) {

  // the payload contents are arbitrary. We are the only ones
  // who will use this data, so store whatever you want here...
  // whatever you store 1) will be visible to everyone (not encrypted),
  // and 2) should not be used by the client... you could encrypt it if 
  // you wanted to... then when the token is sent back to us, we 
  // can just decrypt it. It all depends on what you need to be in
  // the token when you get it back.
  // 
  // In general, it is an "anti-pattern" to store "session data" in 
  // a JWT. Keep session data (ephemeral data that is only useful during
  // the current "login session") on the server, in a DB or redis cache
  // etc. And use express-sessions to manage the use of cookies to 
  // identify which session data record should be retrieved when
  // a request comes in (with a cookie that has a session ID in it).
  //
  // In this repo, we are not using sessions ... but we totally could.
  // Sessions are not incompatible with JWT's.
  //
  // Remember that:
  //
  //    Sessions are server-side stores of data that helps
  //        the server app serve the user request properly.
  //        Session data is short-lived, and typically doesn't
  //        survive between login sessions.
  //
  //    Cookies are just a way for the browser to store a session
  //        identifier, so that the server knows what session data
  //        record to retrieve when a request comes in.
  //
  //    JWT's / tokens are used to authenticate and authorize a user.
  //        they contain information about who the user is, information
  //        about the user (not sensitive information! Things like first
  //        name, last name, etc.), and what the user can do (things like
  //        a "role" the user has, which limits what data they can see, etc.)
  //        Note that a first name and a role are not pieces of information
  //        that "go away" when the user logs out... these are not
  //        candidates for Session data.
  //
  //    Note that you have options. You can store information about the user
  //        in a session record, in a JWT, or in a database. Which you
  //        choose will depend on what the data is, which service(s) will use
  //        it, when it will use it, etc. Knowing which to use will come in 
  //        in time... Generally, you can be successful with almost any
  //        approach. Until you aren't. Then you learn, and move on.
  //
  //  Also, check the IANA registry for "JWT Claims" - you will find a
  //  list of JWT claim identifiers that have been officially registered
  //  to "mean" something in particular.
  const payload = {
    subject: "user",
    username: user.username
  };

  const secret = secrets.jwtSecret;
  
  //
  // there are many options.
  //
  // this one results in "claims" being added by jsonwebtoken
  // to the payload of your token:
  //
  //    {
  //        ...,
  //        iat: xxxxx,
  //        exp: yyyyy,
  //        ...,
  //    }
  //
  //  iat is the number of seconds that had elapsed since midnight 
  //  on Jan 1, 1970 in GMT when the token was created.
  //
  //  exp is the number of seconds that must elapse since midnight
  //  on Jan 1, 1970 in GMT before the token is expired.
  //
  //  Check out "epoch" or "Unix epoch" to learn more about this
  //  standard way of measuring time in software systems.
  //
  const options = {
    expiresIn: '1h'
  };

  //
  // finally, just sign the dang thing and return it already!
  //
  return jwt.sign(payload, secret, options);

}

module.exports = router;
