// init project
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
require('dotenv');
const express = require('express');
const cookieParser = require('cookie-parser');
const hbs = require('hbs');
const authn = require('./libs/authn');
const helmet = require('helmet');
const app = express();
app.use(helmet());


app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

app.use((req, res, next) => {
  if (req.get('x-forwarded-proto') &&
     (req.get('x-forwarded-proto')).split(',')[0] !== 'https') {
    return res.redirect(301, `https://${req.get('host')}`);
  }
  req.schema = 'https';
  next();
});

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, res) => {
  res.render('biometricauthn.html');
});

app.get('/biometricbauthn', (req, res) => {
  res.render('biometricauthn.html');
});

app.use('/authn', authn);

// listen for req :)
const port = 8080;
const listener = app.listen(port, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});

/*!

We will be building a Biometric Authentication system for ATM Transactions where we will use a biometric
 scanner for authentication that will be integrated with Amazon Cognito user pools which is a user directory
  that manages identities in in AWS. Our project will use public-key cryptography which will improve the security 
  mechanism and provide a stronger authentication and easy in ATM machines. We will implement CTAP for fast 
  implementation of FIDO authentication.
There are various methods used for biometric authentications, such as finger printing, facial recognition,
 palm vain reader, and iris scanner. All of them utilize the unique features that every single human being
 has already possessed and can be used instead of the current PINs and card or account numbers for user authentications. 
 In this project, we will mainly focus on two biometric authentication methods: finger printing and facial recognition 
 since the current technology and researches are more mature and extensive on these topics comparing to palm vain readers 
 and iris scanners. 

*/
