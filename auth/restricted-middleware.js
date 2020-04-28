const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const secrets = require('../config/secrets')

module.exports = (req, res, next) => {

const token = req.headers.authorization;
if(token){
  jwt.verify(token, secrets.jwt_secret, (err, decodedToken) =>{
      if (err){
        res.status(401).json({message:"BAD AUTH"});
      } else  {
        decodedToken = decodedToken;
        next();
    } 
  })
}else {
    
    res.status(401).json({message:"BAD AUTH"});
  }
}