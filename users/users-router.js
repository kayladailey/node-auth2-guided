const router = require('express').Router();

const Users = require('./users-model.js');
const restricted = require('../auth/restricted-middleware.js');
const checkRole = require('../auth/check-role-middleware.js');

router.get('/', restricted, checkRole('STUDENT'), (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

//----------------------------------------------------------------------------//
// This would be an example of multiple uses of the higher-order function
// exported from check-role-middleware.js. That function returns a middleware
// function. Below, we are calling it twice, and each time it creates and
// returns a different middleware function that checks for the passed-in value
// in the req.decodedJwt.roles array. 
// 
// The semantic of the following GET /api/users/something handler is that the
// user must have both the 'Student' and 'Tutor' roles in the roles array. If
// either one is missing, the middleware function returned by the exported
// function will end the handling with a call to res.json(), sending an error
// message (and res.status(4xx)). 
// 
// Note also that if the user has 'Admin' in the roles array, both middleware
// functions will pass, because the middleware automatcially calls next() if
// 'Admin' is in the list, regardless of what is passed into the higher order
// function as a parameter. 
//----------------------------------------------------------------------------//
router.get('/something',
  restricted,
  checkRole('STUDENT'),
  checkRole('TUTOR'), (req, res) => {
    // do your thing here.
    res.send('yah');
  })

module.exports = router;
