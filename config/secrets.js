//
// just a module to centralize our JWT signing secret, so we
// don't end up with bugs becaue of mismatched secrets on 
// token signing and token verifying.
//
// typically, in production, you wouldn't use a default
// secret, but in a dev environment, it might make sense.
//
module.exports = {
    jwtSecret: process.env.JWT_SECRET || 'wethotuwasatoad'
}