const OktaJwtVerifier = require('@okta/jwt-verifier');

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: process.env.ISSUER,
  clientId: process.env.CLIENT_ID,
  cacheMaxAge: 60 * 60 * 1000, // 1 hour
  jwksRequestsPerMinute: 10  
});

module.exports = async (req, res, next) => {
    const authorization = req.headers['authorization'];
    const [,token] = authorization.split(' ');

    if (token) {
        oktaJwtVerifier.verifyAccessToken(token)
        .then(jwt => {
          req.tokenClaims = jwt.claims;
          next();
        })
        .catch(err => {
          console.log(err);
        res.status(401);
        });
    } else {
        res.status(401);
        return;
    }
};