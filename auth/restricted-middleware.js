// The old method of verifying that the user is authenticated was to take the
// username/password from headers, and look the user up in the DB... then verify
// the password with bcrype. We needed the bcryptjs package for that. The new
// method doesn't do that, so we don't need it anymore... 
//
// const bcrypt = require('bcryptjs');

// the new way! JWT! 
// And... secrets... 
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

// The old method of verifying that the user is authenticated was to take the
// username/password from headers, and look the user up in the DB... we needed
// the users model for that. The new method doesn't do that, so we don't need it
// anymore... 
// 
// const Users = require('../users/users-model.js');

//----------------------------------------------------------------------------//
// A method to verify that an authorization token is included as a header, and
// that the token is 1) valid, and 2) not expired. (jsonwebtoken checks for
// expired tokens automatically.)
//----------------------------------------------------------------------------//
module.exports = (req, res, next) => {
  // old method: 
  //
  // const { username, password } = req.headers;

  // get the token from the authorization header. 
  // Remember that typically, the client will include the "type" identifier
  // (typically "Bearer") in addition to the token. We are assuming here that
  // there is no type identifier, and that the header value is just the token.
  // But if we were a better-behaved application, we would check, and strip off
  // the type indicator. If we didn't do that, then when it is included (like it
  // almost always is), verification will fail, because we will be trying to
  // verify "Bearer {token}" instead of "{token}". 
  // 
  // See https://www.rfc-editor.org/rfc/rfc6750.html for information on "bearer"
  // tokens. 
  // 
  // See https://tools.ietf.org/html/rfc2617 for information on "basic" and
  // "digest" authorization headers. 
  const token = req.headers.authorization;

  // if we have already verified and decoded the token, no need to do it
  // again... plus, there may be some methods that modify req.decodedJwt, and
  // then a later middleware that calls this restricted-middleware, and we don't
  // want to overwrite req.decodedJwt with another call to this method, if we
  // have already verified the token. 
  if (req.decodedJwt) {
    next();
  } else if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedJwt) => {
      // if the token doesn't verify
      if (err) {
        res.status(401).json({ you: "shall not pass!" });
        // if it DOES...
      } else {
        req.decodedJwt = decodedJwt;
        next();
      }
    })
  } else {
    res.status(401).json({ you: "can't touch that." });
  }

  //----------------------------------------------------------------------------//
  // This is the old version of this restricted middleware... what we replaced. 
  //----------------------------------------------------------------------------//
  // if (username && password) {
  //   Users.findBy({ username })
  //     .first()
  //     .then(user => {
  //       if (user && bcrypt.compareSync(password, user.password)) {
  //         next();
  //       } else {
  //         res.status(401).json({ message: 'Invalid Credentials' });
  //       }
  //     })
  //     .catch(error => {
  //       res.status(500).json({ message: 'Ran into an unexpected error' });
  //     });
  // } else {
  //   res.status(400).json({ message: 'No credentials provided' });
  // }
};
