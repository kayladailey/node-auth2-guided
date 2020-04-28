const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model.js');
const secrets = require('../config/secrets')

// for endpoints beginning with /api/auth
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


//LOGIN 
router.post('/login', (req, res) => {
  let { username, password } = req.body;


  //ADDING JWT
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
          const token = generateToken(user)

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          jwt_token: token
      
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//TOKEN FUNCTION (generates and returns the token)
function generateToken(user){

  const payload = {
    subject: user.id,
    userid: user.username,
    roles: ['STUDENT']
  };

  const secret = secrets.jwt_secret;
  
const options = {
  expiresIn: "30m"
};

const token = jwt.sign(payload, secret, options);
console.log(token);
return  token;
}

module.exports = router;
