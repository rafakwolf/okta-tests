const OktaJwtVerifier = require('@okta/jwt-verifier');

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: process.env.ISSUER,
  clientId: process.env.CLIENT_ID,
  cacheMaxAge: 60 * 60 * 1000, // 1 hour
  jwksRequestsPerMinute: 10  
});

module.exports = async (req, res, next) => {
    // console.log(req);
    const authorization = req.headers['authorization'];
    const [,token] = authorization.split(' ');

    if (token) {
        oktaJwtVerifier.verifyAccessToken(token)
        .then(jwt => {
          // the token is valid (per definition of 'valid' above)
          console.log(jwt.claims);
          req.tokenClaims = jwt.claims;
          next();
        })
        .catch(err => {
          // a validation failed, inspect the error
          console.log(err);
        res.status(401);
        });
    } else {
        res.status(401);
        return;
    }
};