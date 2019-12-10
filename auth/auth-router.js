const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

const Users = require('../users/users-model.js');

// for endpoints beginning with /api/auth

//----------------------------------------------------------------------------//
// We didn't do this in class, but it makes sense to return a token when someone
// registers... why make them log in when they just barely provided a new
// username and password? Just return them a token, so they can begin using it
// right away... 
//----------------------------------------------------------------------------//
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      // pass the created user into the genToken() method, and get the token
      const token = genToken(saved);
      // return the user object, and the token.
      res.status(201).json({ created_user: saved, token: token });
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//----------------------------------------------------------------------------//
// When someone successfully authenticates, reward them with a token, so they
// don't have to authenticate again. 
//----------------------------------------------------------------------------//
router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        // pass the found user into the genToken() method, and get the token
        const token = genToken(user);
        // return the found user's username, and the token"
        res.status(200).json({ username: user.username, token: token });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//----------------------------------------------------------------------------//
// This is a helper method that helps us stay DRY (we generate tokens in both
// the POST /api/auth/register handler, and the POST /ap/auth/login handler).
// Uses the same pattern as our test handler for GET /token in server.js. 
//----------------------------------------------------------------------------//
function genToken(user) {

  // create the payload...
  const payload = {
    userid: user.id,
    username: user.username,
    // this could be more sophisticated, like looking up the user's "roles" from
    // a database, and adding them to this token. A hierarchy of privileges
    // could be established as well, and an entire library for managing rights.
    // This is not a new problem, and many creative patterns and packages have
    // been created to solve it (the ability to manage privileges/roles, etc.)
    // If you are interested, look up these topics:
    //    * Role-based access control (RBAC)
    //      https://en.wikipedia.org/wiki/Role-based_access_control
    //    * Access Control List (ACL)
    //      https://en.wikipedia.org/wiki/Access-control_list 
    // 
    // For now, we are just hard-coding a string in an array, and checking
    // elsewhere to see if a certain string is included in this array... pretty
    // primitive, but you get the idea. 
    roles: ['Student']
    // other things: rights/privileges? other info?     
  };
  // the syntax for specifing an expiration time with jsonwebtoken package is
  // somewhat intuitive. In addition to this ASCII/text method, you could
  // calculate "Seconds Since Epoch", which is known through Unix-like systems
  // as the number of elapsed seconds since midnight, January 1, 1970, in the
  // UTC timezone (aka GMT). See https://en.wikipedia.org/wiki/Epoch_(computing)
  // Note that specifying an "expires in" value specifies an amount of time that
  // must elapse for the token to be considered "expired". 
  //
  // For instructions you should follow (both on the client and server side)
  // with respect to JWT's,  you should read the RFC (Request For Comments)
  // document that defines the JWT format and use. See
  // https://tools.ietf.org/html/rfc7519. 
  // 
  // For an understanding of what an RFC is, enjoy this little bit of light
  // reading: https://en.wikipedia.org/wiki/Request_for_Comments 
  // 
  // See section 4.1.4, as well as the definition of "NumericDate" in Section 2.
  // If you think that managing time on computers and across the Internet and
  // around the world is simple, you have not studied the topic... dive in, have
  // fun! 
  const options = { expiresIn: '1h' };
  const token = jwt.sign(payload, secrets.jwtSecret, options);

  return token;
}

module.exports = router;
