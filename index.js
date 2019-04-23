require('dotenv').config();

const okta = require('@okta/okta-sdk-nodejs');
const oktaAuth = require('@okta/okta-auth-js');
const {hashToObject} = require('@okta/okta-auth-js/lib/oauthUtil');
const request = require('request');
const uuid4 = require('uuid4');
const bodyParser = require('body-parser');
const express = require('express');
const queryString = require('query-string');
const fs = require('fs');
const sendEmailVerification = require('./email-verification');
const tokenMiddleware = require('./token-middleware');
const axios = require('axios').default;


const app = express();
app.use(bodyParser.json());

const client = new okta.Client({
    orgUrl: process.env.ORG_URL,
    token: process.env.API_TOKEN
});

const authConfig = {
    url: process.env.ORG_URL,
    issuer: process.env.ISSUER,
    clientId: process.env.CLIENT_ID,
};

const authClient = new oktaAuth(authConfig);

app.get('/', (_req, res) => {
    fs.readFile(__dirname + '/public/index.html', 'utf8', (err, text) => {
        res.send(text);
    });
});

// create user
app.post('/user', async (req, res) => {
    const newUser = {
        profile: {
            firstName: req.body.name,
            lastName: req.body.lastName,
            email: req.body.username,
            login: req.body.username,
        },
        credentials: {
          password : {
            value: req.body.password
          }
        }
    };
    try {
        const user = await client.createUser(newUser, {activate: false});
        res.send(user);
        sendEmailVerification(user.id, client);
    } catch (e) {
        console.log(e);
        res.send(e);
    }
});

// retrieve the user
app.get('/user/:id', async (req, res) => {
    const user = await client.getUser(req.params.id);
    res.send(user);
});

// retrieve all users
app.get('/user', async (req, res) => {
    const users = await client.listUsers();
    res.send(users);
});

// dummy route to redirect
app.get('/dummy', async (req, res) => {
    res.send('success');
});


async function requestAccessTokens(sessionToken) {
    const state = uuid4();
    const nonce = uuid4();

    const query = {
        client_id: process.env.CLIENT_ID,
        response_type:'id_token token',
        response_mode: 'fragment',
        scope: 'openid profile',
        redirect_uri: 'http://localhost:3009/dummy',
        state,
        nonce,
        prompt: 'none',
        sessionToken,
    };

    const str = queryString.stringify(query);

    const response = await axios.get(`${process.env.AUTH_URL}?${str}`);
    const hash = response.request.res.responseUrl.replace('http://localhost:3009/dummy','');
    const tokens = hashToObject(hash);
    return tokens;
}


// login
app.post('/login', async (req, res) => {

    const result = await authClient.signIn({
        username: req.body.username,
        password: req.body.password
    });

    switch (result.status) {
        case 'SUCCESS':
            const tokens = await requestAccessTokens(result.sessionToken);
            res.send(tokens);
            break;
        case 'MFA_REQUIRED':
            if (result.factors.length > 0) {
                const factor = result.factors[0];
                res.send({
                    stateToken: result.data.stateToken,
                    status: result.status,
                    factorId: factor.id,
                    factorType: factor.factorType,
                });
            }
            break;
         default:
            break;
    }
});

app.post('/verify-mfa', tokenMiddleware, async (req, res) => {
    const {mfaCode, factorId, stateToken} = req.body;

    const requestUrl = `https://dev-712076.okta.com/api/v1/authn/factors/${factorId}/verify`;

    request.post(requestUrl, {
        json: {
            "stateToken": stateToken,
            "passCode": mfaCode
        } 
    },
     async (error, response, body) => {
        if (error) {
            res.status(500).send(error);
            return;
        }

        const {sessionToken, status} = body;
        if (status === 'SUCCESS') {
            const tokens = await requestAccessTokens(sessionToken);
            res.send(tokens);
        } else {
            res.status(response.statusCode).send(body);
        }

      });

});

app.get('/google', async (req, res) => {
    const state = uuid4();
    const nonce = uuid4();

    const redirectUrl = 
        `https://dev-712076.okta.com/oauth2/v1/authorize?
idp=0oahls96dPCUpExcL356&
client_id=${process.env.CLIENT_ID}&
response_type=${'id_token+token'}&
response_mode=${'fragment'}&
scope=${'openid+profile'}&
redirect_uri=${'http://localhost:3009/dummy'}&
state=${state}&
nonce=${nonce}`.replace(/\n/gm, '');

    res.redirect(redirectUrl);
});

app.post('/reset-password', tokenMiddleware, async (req, res) => {
   const userId = req.userContext.userinfo.uid;
   const result = await client.resetPassword(userId);
   res.send(result);
});

app.post('/add-mfa', tokenMiddleware, async (req, res) => {
    try {
        const userId = req.userContext.userinfo.uid;
        const factor = {
            factorType: 'token:software:totp',
            provider: 'Google'
          };        
        const result = await client.addFactor(userId, factor)
        res.send(result);
    } catch (e) {
        res.status(500).send(e);
    }
});

app.post('/enable-mfa', tokenMiddleware, async (req, res) => {
    try {
        const userId = req.userContext.userinfo.uid;
        const passCode = req.body.passCode;
        const verification = {
            passCode
          };        
        const result = await client.activateFactor(userId, 'ufths2w2jbu7ZVU6E356', verification);
        res.send(result);
    } catch (e) {
        res.status(500).send(e);
    }
});

app.post('/list-mfa', tokenMiddleware, async (req, res) => {
    try {
        const userId = req.userContext.userinfo.uid;
        const result = await client.listFactors(userId);
        res.send(result);
    } catch (e) {
        res.status(500).send(e);
    }
});

oidc.on('ready', () => {
    app.listen(3009, () => {
        console.log('Running on port 3009');
    });
});