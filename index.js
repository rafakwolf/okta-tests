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


const app = express();
app.use(bodyParser.json());

const client = new okta.Client({
    orgUrl: 'https://dev-712076.okta.com/',
    token: '00lIPSWnr4r27Tks5jJlnp_2RuP60V6s6zUUd1nx1w'
});

const authConfig = {
    url: 'https://dev-712076.okta.com/',
    issuer: 'https://dev-712076.okta.com/oauth2/default',
    clientId: '0oahhk8o2NEZR7YfW356',
    redirectUri: 'http://localhost:8080/authorization-code/callback',
    tokenManager: {
      storage: 'sessionStorage'
    }
};

const authClient = new oktaAuth(authConfig);

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
        const user = await client.createUser(newUser);
        res.send(user);
    } catch (e) {
        console.log(e);
        res.send(e);
    }
});

// retriever the user
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

    const query = {
        client_id: '0oahhk8o2NEZR7YfW356',
        response_type:'id_token token',
        response_mode: 'fragment',
        scope: 'openid profile',
        redirect_uri: 'http://localhost:3009/dummy',
        state,
        nonce: '123456',
        prompt: 'none',
        sessionToken,
    };

    const str = queryString.stringify(query);

    request(`https://dev-712076.okta.com/oauth2/v1/authorize?${str}`, function (error, response) {

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
    // state={state}&nonce={nonce}
});


app.listen(3009, () => {
    console.log('Running on port 3009');
});