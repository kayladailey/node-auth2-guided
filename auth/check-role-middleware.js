
//----------------------------------------------------------------------------//
// This is middleware that can be used to add a check for a specific role in the
// token. 
//
// When a user successfully logs in or registers, a token is created and saved
// on the request object. If the request comes in AFTER login/registration, it
// should include the token, which, upon initial verification, should be saved
// to the req object as req.decodedJwt. 
//
// This middleware method checks the decodedJwt for a "roles" property (which,
// per our app design, should be an array of strings.)
//
// This technique uses a "higher order function" to manufacture and return a
// middleware function. We aren't exporting a middleware function. We are
// exporting a middleware function creator. By passing in a value to the
// creator, you get back a middleware function that checks for the value in the
// array of roles on the token. In this way, you can call this exported method
// multiple times with different "role" values, and each time, you will get a
// middleware function that checks for the passed-in role value in the
// req.decodedJwt.roles array. 
//
// There is a mild attempt at implementing a hierarchical roles capability... If
// the role that is being sought (the value passed in to the higher-order
// function) doesn't exist in req.decodedJwt.roles, but if the value 'Admin'
// does, we will move on to the next middleware in the chain. The semantic here
// is that if you have the 'Admin' role, it doesn't matter what other roles you
// may or may not have: you are allowed to do anything; therefore, "next()". 
//
// This is in no way complete or well-thought-out... again, RBAC systems are
// prevalent ... do some research... it's a big field, and requires very careful
// thought and implementation. See the notes in ./auth/auth-router.js under the
// genToken() function for more info and some links for bathroom or poolside
// reading. 
//----------------------------------------------------------------------------//
module.exports = (role) => {
    return function (req, res, next) {
        if (req.decodedJwt.roles && req.decodedJwt.roles.includes(role)) {
            next();
        } else if (req.decodedJwt.roles && req.decodedJwt.roles.includes('Admin')) {
            next();
        } else {
            res.status(403).json({ you: "don't have permission" });
        }
    }
}