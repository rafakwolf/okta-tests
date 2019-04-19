const okta = require('@okta/okta-sdk-nodejs');
const jwt = require('@okta/jwt-verifier');
const oktaAuth = require('@okta/okta-auth-js');
const request = require('request');
const btoa = require('btoa');
const uuid4 = require('uuid4');
const bodyParser = require('body-parser');
const express = require('express');
const queryString = require('query-string');
const fs = require('fs');
const { ExpressOIDC } = require('@okta/oidc-middleware');
const sendEmailVerification = require('./email-verification');
require('dotenv').config();
const tokenMiddleware = require('./token-middleware');


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

const oidc = new ExpressOIDC({
    issuer: process.env.ISSUER,
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    appBaseUrl: 'http://localhost:3009',
    scope: 'openid profile'
  });

app.get('/', (req, res) => {
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

// login
app.post('/login', async (req, res) => {

    const result = await authClient.signIn({
        username: req.body.username,
        password: req.body.password
    });

    const sessionToken = result.sessionToken;
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

    request(`${process.env.AUTH_URL}?${str}`, function (error, response) {

        if (error) {
            res.status(500).send(error);
        }

        const parts = response.request.uri.hash.split('&');
        let tokens = {};
        parts.forEach(item => {
            tokens[item.split('=')[0]] = item.split('=')[1];
        });
        res.send(tokens);
    });
});

app.post('/google', async (req, res) => {
    // https://dev-712076.okta.com/oauth2/v1/authorize?
    // idp=0oahls96dPCUpExcL356&
    // client_id={clientId}&
    // response_type={responseType}&
    // response_mode={responseMode}&
    // scope={scopes}&
    // redirect_uri={redirectUri}&
    // state={state}&
    // nonce={nonce}
});

app.post('/reset-password', tokenMiddleware, async (req, res) => {
   const userId = req.tokenClaims.uid;
   const result = await client.resetPassword(userId);
   res.send(result); 
});

oidc.on('ready', () => {
    app.listen(3009, () => {
        console.log('Running on port 3009');
    });
});