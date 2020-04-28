const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const secrets = require('../config/secrets')

module.exports = (req, res, next) => {

  try{
const token = req.headers.authorization.split("")[1];
console.log(token);


if(token){
  jwt.verify(token, secrets.jwt_secret, (err, decodedToken) =>{
      if (err){
        throw new Error(err)
        res.status(401).json({message:"BAD AUTH"});
      } else  {
        throw new Error("Bad Authorization")
        req.decodedToken = decodedToken;
        next();
    } 
  })
}else {
    
    res.status(401).json({message:"BAD AUTH"});
  }
} catch (err){
  res.status(401).json(err.message);
}
};