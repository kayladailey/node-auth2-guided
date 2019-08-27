const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

//
// this is our fancy JWT module.
// there are many JWT modules... some of them
// have security problems in them... be careful
// which one you use! This one is a good one...
//
// generally, when I look for a good module to
// use, I google-fu to see if anyone is complaining
// about a module, etc.
//
const jwt = require('jsonwebtoken');


const authRouter = require('../auth/auth-router.js');
const usersRouter = require('../users/users-router.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use('/api/auth', authRouter);
server.use('/api/users', usersRouter);

server.get('/', (req, res) => {
  res.send("It's alive!");
});

//
// this is just a sample endpoint for generating
// a token... it isn't useful at all, because
// we aren't authenticating the user in any way.
//
// anyone who does a GET /token will get a token back.
// 
// again, we just wrote it to get experience using the
// jsonwebtoken module.
//
// don't forget to .require('jsonwebtoken') up above!
//
server.get('/token', (req,res) => {
  
  const payload = {
    subject: "user",
    username: "skirkby",
    favoriteChili: "habanero"
  };

  // this is a hard-coded secret.
  // bad form! use secrets.js instead!
  const secret = "wethotuwasatoad";
  
  //
  // read up on all the options... this one
  // should cause the jwt.verify() method to
  // fail if the token has expired... when you
  // specify a length of time (from "right now") 
  // that the token is good, a "claim" is added
  // to the payload that indicates when the token
  // should expire (as a number of seconds since 
  // midnight, January 1, 1970 GMT - a.k.a. "seconds
  // since epoch" - look it up, I dare you.)
  //
  // there are 2 claims that using expiresIn adds to the
  // payload:
  //
  // {
  //     iat: xxxxx,
  //     exp: yyyyy 
  // }
  //
  // iat is when the token was created, and exp is when
  // the token will expire.
  //
  // you can convert these values to an actual date/time
  // using new Date(xxxxx * 1000) etc.
  //
  // https://www.epochconverter.com/programming#javascript
  //
  const options = {
    expiresIn: '1h'
  };


  //
  // jwt.sign() just takes the payload, the secret, and
  // (optionally, no pun intended) the options.
  // 
  // it could also take a callback that could handle errors
  // if there are any.
  //
  // if you are interested, look into the different signing
  // algorithms that can be used. Of particular interest to me
  // are the public/private key algorithms, which don't require
  // a shared symmetric secret for generating the signature.
  //
  const token = jwt.sign(payload, secret, options);
  console.log(token);

  res.json(token);

})

module.exports = server;
