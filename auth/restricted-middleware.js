// 
// we no longer need bcrypt in this middleware, because
// we are not confirming "authentication" or "authorization"
// using a username and password.
//
// See this site for a sequence diagram that shows 
// jwt's, cookies/sessions, and bcrypt all at work together:
//
//      http://bit.ly/2U6Roth
//
//
//const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

const Users = require('../users/users-model.js');

//
// here we get the token that the client/browser sent in.
// what? you say that browser didn't include the token
// in its request? NO SOUP FOR YOU!
//
// the browser application must add the token to an
// Authorization header.
//
// what? The browser added it to a different header?
// NO SOUP FOR YOU!
//
// Seriously? The browser app added the token to the
// request body? That's nice. NO SOUP FOR YOU!
//
// The token must be added to a header named "Authorization".
// Why? Because that's where we are going to look for it, below.
//
// Note that in the lecture, we just made the Authorization header
// value equal to the token string. But in reality, we should have 
// used the "bearer" scheme declaration in front of it.
//
// So, instead of just 
//        Authorization: {token_string}
// it should be
//        Authorization: bearer {token_string}
//
// There are numerous Authorization header "schemes", each of
// which is just a clue to the server about how to interpret
// the header value (minus the scheme name).
//
// "bearer" is the scheme that means "what follows is a token".
//
// Yeah, I know. A scheme named "token" would have made 
// too much sense. C'est la vie.
//
module.exports = (req, res, next) => {

  const tokenHeader = req.headers.authorization;
  

  if (tokenHeader) {
    const tokenStrings = tokenHeader.split(" ");
    // at this point, tokenStrings[0] should be "bearer",
    // and tokenStrings[1] should be our token.

    // if our scheme is "bearer", and there is a token after it...
    if (tokenStrings[0].toUpperCase() === 'BEARER' && tokenStrings[1]) {
      jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
        if (err) {
          // bad token!
          res.status(401).json({message: 'error verifying token', error: err});
        } else { 
          // decodedToken! next()!
          //
          // we add decodedToken to the req object just so that 
          // future middleware methods can have access to it...
          // in our example here, no middleware methods are accessing
          // it, but it makes sense to store it... our app may grow!
          //
          req.decodedJwt = decodedToken;
          next();
        }
      });
    // the scheme isn't "bearer", or there was no token after "bearer"
    } else {
      res.status(401).json({message:"invalid scheme, or no token after scheme name."})
    }
  // no authorization header was sent
  } else {
    res.status(401).json({message: 'missing Authorization header'});
  }

};
