/**

IntitiateAuth (1)
When the user select on transaction authorization button on the ATM machines
 the authentication process starts with the Amazon Cognito InitiateAuth API by taking user credentials to the CUSTOM_AUTH.


  CUSTOM_CHALLENGE (2)
After initiating authentication request the Amazon Cognito triggers Auth Challenge
 Lambda for the user to solve in order for the authentication process to continue
2.3.3 Biometric Scanner activation (3)
The biometric scanner is activated and verifies that credentials exist for the identifier
 and that the relying party matches the one that is bound to the credentials. This is done by a
  function call navigator.credentials.get API that is present in the ATM devices that support FIDO
 

  
  Authentication response (4)
The Authentication process continues where the respondToAuthChallenge API sends response to the Amazon Cognito.
2.3.5 Response to the Auth Challenge Lambda (5)
Amazon Cognito sends the response to the Verify Auth Challenge Lambda trigger. This trigger extracts the
 public key from the user profile, parses and validates the credentials response, and if the signature is 
 valid, it responds with success. This is performed in VerifyAuthChallenge Lambda trigger.

 
 Respond to the AuthChallenge (6)
Lastly, Amazon Cognito sends the control again to Define Auth Challenge to determine the next step. If the
 results from Verify Auth Challenge indicate a successful response, authentication succeeds and Amazon Cognito 
 responds with ID, access, and refresh tokens.
 */

var crypto = require("crypto");

exports.handler = async (event) => {
    console.log(event);
   
   //--------get private challenge data
    const challenge = event.request.privateChallengeParameters.challenge;
    const credId = event.request.privateChallengeParameters.credId;
    
    //--------publickey information
    var publicKeyCred = event.request.userAttributes["custom:publicKeyCred"];
    var publicKeyCredJSON = JSON.parse(Buffer.from(publicKeyCred, 'base64').toString('ascii'));
    
    //-------get challenge ansower
    const challengeAnswerJSON = JSON.parse(event.request.challengeAnswer);
    
    const verificationResult = await validateAssertionSignature(publicKeyCredJSON, challengeAnswerJSON);
    console.log("Verification Results:"+verificationResult);
    
    if (verificationResult) {
        event.response.answerCorrect = true;
    } else {
        event.response.answerCorrect = false;
    }
    return event;
};

async function validateAssertionSignature(publicKeyCredJSON, challengeAnswerJSON) {
    
    var expectedSignature = toArrayBuffer(challengeAnswerJSON.response.signature, "signature");
    var publicKey = publicKeyCredJSON.publicKey;
    var rawAuthnrData = toArrayBuffer(challengeAnswerJSON.response.authenticatorData, "authenticatorData");
    var rawClientData = toArrayBuffer(challengeAnswerJSON.response.clientDataJSON, "clientDataJSON");

    const hash = crypto.createHash("SHA256");
    hash.update(Buffer.from(new Uint8Array(rawClientData)));
    var clientDataHashBuf = hash.digest();
    var clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

    const verify = crypto.createVerify("SHA256");
    verify.write(Buffer.from(new Uint8Array(rawAuthnrData)));
    verify.write(Buffer.from(new Uint8Array(clientDataHash)));
    verify.end();
    
    var res = null;
    try {
        res = verify.verify(publicKey, Buffer.from(new Uint8Array(expectedSignature)));
    } catch (e) {console.error(e);}

    return res;
}

function toArrayBuffer(buf, name) {
    if (!name) {
        throw new TypeError("name not specified");
    }

    if (typeof buf === "string") {
        buf = buf.replace(/-/g, "+").replace(/_/g, "/");
        buf = Buffer.from(buf, "base64");
    }

    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not convert '${name}' to ArrayBuffer`);
    }

    return buf;
}
/**

IntitiateAuth (1)
When the user select on transaction authorization button on the ATM machines
 the authentication process starts with the Amazon Cognito InitiateAuth API by taking user credentials to the CUSTOM_AUTH.


  CUSTOM_CHALLENGE (2)
After initiating authentication request the Amazon Cognito triggers Auth Challenge
 Lambda for the user to solve in order for the authentication process to continue
2.3.3 Biometric Scanner activation (3)
The biometric scanner is activated and verifies that credentials exist for the identifier
 and that the relying party matches the one that is bound to the credentials. This is done by a
  function call navigator.credentials.get API that is present in the ATM devices that support FIDO
 

  
  Authentication response (4)
The Authentication process continues where the respondToAuthChallenge API sends response to the Amazon Cognito.
2.3.5 Response to the Auth Challenge Lambda (5)
Amazon Cognito sends the response to the Verify Auth Challenge Lambda trigger. This trigger extracts the
 public key from the user profile, parses and validates the credentials response, and if the signature is 
 valid, it responds with success. This is performed in VerifyAuthChallenge Lambda trigger.

 
 Respond to the AuthChallenge (6)
Lastly, Amazon Cognito sends the control again to Define Auth Challenge to determine the next step. If the
 results from Verify Auth Challenge indicate a successful response, authentication succeeds and Amazon Cognito 
 responds with ID, access, and refresh tokens.
 */