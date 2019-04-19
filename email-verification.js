
// needs template customization 
function sendEmailVerification(userId, oktaCli) {
    console.log('sending confirmation email...');

    const requestUrl = `https://dev-712076.okta.com/api/v1/users/${userId}/lifecycle/activate?sendEmail=true`;

    oktaCli.http.postJson(requestUrl, {
        body: {
        }
      })
        .then((session) => {
          console.log(session)
        })
        .catch((err) => {
          console.log(err)
        });
}

module.exports = sendEmailVerification;