const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
//----------------------------------------------------------------------------//
// This is our fancy JWT module. There are many JWT modules... some of them have
// security problems in them... be careful which one you use! This one is a good
// one...
//
// Generally, when I look for a good module to use, I google-fu to see if anyone
// is complaining about a module, etc.
//----------------------------------------------------------------------------//
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

//----------------------------------------------------------------------------//
// This was our test to get experience in generating and returning a token. 
//
// jwt.sign() is used to 
//    * identify and create the correct "headers" for the JWT,
//    * create the payload (including adding other "claims" that we didn't add,
//      such as "iat" and "exp", which are the timestamps for when the token was
//      created, and when it will expire, respectively.) 
//    * create the "verify signature" section, which is an encoded version of an
//      encrypted string, made from the headers and payload, together with a
//      "secret". 
//    * includes any additional claims needed for the options selected (if any)
// 
//----------------------------------------------------------------------------//
server.get('/token', (req, res) => {

  const payload = {
    subject: 'thisuser',
    userid: 'skirkby',
    favoriteChili: 'habanero'
  };

  const secret = 'wethotuwasatoad';
  const options = {
    expiresIn: '1h'
  };

  const token = jwt.sign(payload, secret, options);

  res.json(token);
})

module.exports = server;
