
//----------------------------------------------------------------------------//
// Just a module to centralize our JWT signing secret, so we don't end up with
// bugs becaue of mismatched secrets on token signing and token verifying.
// 
// Also prevents us from having to save secrets in a public SCM system like
// github, where it could be vulnerable. If you design your app to use a secret
// from an environment variable, then process.env.JWT_SECRET works. You could
// use the .ENV package to save environment variable values in a .env file that
// is not uploaded when you check in, or set the secret in the environment. 
// 
// A token will not verify if the verification process doesn't have access to
// the same "secret" key that was used to create the token to begin with. 
//
// Typically, in production, you wouldn't use a default secret, but in a dev
// environment, it might make sense.
//----------------------------------------------------------------------------//
module.exports = {
    jwtSecret: process.env.JWT_SECRET || 'wethotuwasatoad'
}