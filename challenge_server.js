//------------------------------------------------------------------------
//
//	challenge-server.js
//
// 	Author: David Gentry
// 	Date: 9/21/2018
//
//	This file is the server portion of the coding challenge for bitpay.
//	It will accept a user password, authenticate a user, store the users
//	password securly, accept a user-supplied public key, accept a message
//	signed by the user's private key and attempt to verify using the previously 
//	submitted public key.
// 
//	The server uses express to provide a port listener for the client callers
//
//	The server uses the bcryptjs library to hash the user's passwords for
// 	security.
//
//	The server stores data in memory
//
// 	The server allows for registering new users
//  When a user logs in with the previously registered username/password, they'll
//	get a limited time session ID that can be used with other commands
//
//	The server will only store a public key for a user after logging in and
//	using the returned sessionID.
//
// 	The server will accept a signed message from any user, providing just a 
// 	username. The signed message will be verified using the previously stored
// 	public key (if any)
//------------------------------------------------------------------------
'use strict'

var express = require('express');					// the main listener module
var bodyparser = require('body-parser');			// extract data from PUTs
var bcrypt = require('bcryptjs');					// using bcryptjs 
var crypto = require('crypto');						// crypto library for verifying signatures

var app = express();								// create the listener

var registeredUsers = [];							// array of users registered (currently only in memory, lost when the server restarts) - may save to mongo later

// current user/pw
var username = '';									// current user being processed
var pword = '';										// current hashed password being processed
var sessionID = '';									// current sessionID  - only for logged in users
var extendedfailure = '';							// better results reporting
var salt = bcrypt.genSaltSync(10);					

// local utility functions

// - check the password sent in against the hashed version stored
function checkPw( index, in_pw ) {
	var retrieved_pw = registeredUsers[index].password;
	if (bcrypt.compareSync(in_pw, retrieved_pw) === false ) {
		console.log("checkPw(): failed password comparison!");
		return false;
	} else {
		console.log("checkPw(): passed password comparison");
		return true;
	}
}

// - findUser - find the username in local storage
function findUser( username ) {
	// since we are using an array to store usernames/passwords, return the index of the user found, else return -1
	for( var i=0; i<registeredUsers.length; i++ ) {
		if( username === registeredUsers[i].username ) {
			return i;
		}
	}
	return -1;
}

// - addToRegisteredUsers - add this username/password to the local storage
function addToRegisteredUsers( obj ) {
	// alter this function if mongoDB is used later
	console.log("pushing the new user to the storage");
	registeredUsers.push(obj);
	//obj = {};
}

// - clearSessionID - reset the sessionID on timeout to force the user to re-login
function clearSessionID() {
	// we have a hardcoded timeout on sessionIDs.  
	console.log("clearing sessions ID");
	sessionID = '';
	username = '';
	pword = '';
}

// - checkCurrentSessionID - see if the current sessionID matches the one passed in
function checkCurrentSessionID ( sessID ) {
	return (sessionID === sessID)?true:false;
}

// - pem_format - function to restore a public key stored to PEM format for the verification to parse correctly
function pem_format( inkey ) {

	var sectionsize = 64;
	var st = 0;
	var end = 0;
	
	//quick function to restorm PEM format for verification in case it was changed at the storage procedure
	// this is not how I like to do this. This is a temp workaround due to time constraints - potential problem that needs to be altered on next commit
	
	var outkey = '';
	var nlcount = 0;
	var tempstr = '';
	var header = '-----BEGIN PUBLIC KEY-----';
	var footer = '\n-----END PUBLIC KEY-----';
	
	for(var i=0;i<inkey.length; i++) {
		if( inkey[i] === '\n' ) {
			nlcount++;
		}
	}
	
	if( nlcount === 0 ) {		// if no newlines, then it was altered, restore them for base64 encoding
		var subs = '';
		outkey = header + '\n';
		//get the data between BEGIN and END from the input
		tempstr = inkey.substr(header.length, (inkey.length - header.length - footer.length)+1);
		
		var str = tempstr;
		var chunks = str.match(/.{1,64}/g);
		var new_value = chunks.join("\n");
		new_value += footer;
		outkey += new_value;

	} else {
		outkey = inkey;
	}

	return (outkey);
}

// --------------------------------------------------------------------
// Process functions for the API endpoints

// - processStoreKey - see if the user is registered and authenticated, then store the public key they sent into local storage
function processStoreKey( body ) {
	var session_id;
	var index;
	var key;
	
	console.log(body);
	// the user can only use this API if they've logged in and their sessionID hasn't expired, else they need to login again
	
	// sanity check - did they pass a session ID?
	if (typeof body.sessID == undefined ) {
		extendedfailure = "no sessionID sent";
		console.log(extendedfailure);
		return false;
	} else {
		session_id = body.sessID.trim(); 
	}
	if (checkCurrentSessionID(session_id) === false) {
		extendedfailure = " session ID not valid";
		console.log(extendedfailure);
		return false;
	}
	
	// sanity check on public key parameter:
	if( typeof body.pubkey == undefined) {
		extendedfailure = "no publickey sent";
		console.log(extendedfailure);
		return false;
	} else {
		key = body.pubkey;
		//console.log("setting key to " + key);
	}
	
	// if sessionID is not timedout, then the username variable should be set to the last one that logged in
	index = findUser(username);
	
	if( index !== -1) {
		console.log("storing public key for user: " + username);
		registeredUsers[index].publickey = key;
		console.log(JSON.stringify(registeredUsers));
	} else {
		extendedfailure = "user not found";
		console.log(extendedfailure);
		return false;
	}
	
	return true;
	
}

// - processRegisterUser - if not already registered, save their username and password and make a spot for a public key
function processRegisterUser( body ) {
	var obj = {};
	
	// sanity check, did they pass a username?
	if( typeof body.username == undefined ) {
		extendedfailure = "no username specified";
		console.log(extendefailure);
		return false;
	}
	
	username = body.username.trim();

	// first, check to see if this username is already in the registered storage
	if( findUser(username) !== -1 ) {
		extendedfailure = "username already registered";
		console.log(extendedfailure);
		return false;
	}
	console.log("username = " + username + ", password = " + body.password);
	
	// this hash can be slow
	pword = bcrypt.hashSync(body.password, salt);
	
	// store the user in the array of users
	obj.username = username;
	obj.password = pword;
	obj.publickey = '';								// make space for a saved public key if they choose to send one
	
	// add this to the storage array 
	addToRegisteredUsers(obj);
	obj = {};
	
	//console.log(JSON.stringify(registeredUsers));
	return true;
}

// - processSignedMessage - look up the username, and his stored key, then try to verify the message using the signature and key
function processSignedMessage( body ) {
	// as usual, the sanity checks: do all 3 fields exist? username, message, signature
	console.log(JSON.stringify(body));
	if( typeof body.username == undefined ) {
		extendedfailure = "missing username";
		console.log(extendedfailure);
		return false;
	}
	if (typeof body.message == undefined ) {
		extendedfailure = "missing message";
		console.log(extendedfailure);
		return false;
	}
	if (typeof body.signature == undefined ) {
		extendedfailure = "missing signature";
		console.log(extendedfailure);
		return false;
	}
	
	var username = body.username.trim();
	var signature = body.signature;
	var index = -1;
	var pubkey = '';
	// does this user exist? and if so, did they store their public key already?
	
	index = findUser(username);
	console.log("index = " + index);
	if( index === -1 ) {
		extendedfailure = "user not registered";
		console.log(extendedfailure);
		return false;
	} else {
		console.log(JSON.stringify(registeredUsers[index]));
		pubkey = pem_format(registeredUsers[index].publickey);		
		//console.log("pubkey = " + pubkey);
		if( pubkey === '' ) {
			extendedfailure = "no publickey found for this user";
			console.log(extendedfailure);
			return false;
		}
	}
	// if we made it here, we found the user and the publickey, now check the signature
	
	var verifyagent = crypto.createVerify('sha256');	// same as used in the client
	var message = body.message;							// don't trim() this one in case leading/following spaces were part of the hash
	verifyagent.update(message);						// load the message into the verifyagent
	verifyagent.end();
	
	var verified = verifyagent.verify(pubkey, signature, 'hex');

	if( verified === true ) {
		console.log("Signature verified!");
		return true;
	} else {
		extendedfailure = "Signature failed verification";
		console.log(extendedfailure);
		return false;
	}
}

// - processLogin - look up the username, check the password sent against the hashed stored value in storage, set a session ID for them to use
function processLogin( body ) {
	var user, pw;
	var indx = -1;
	
	sessionID = '';
	
	// sanity checks, in case someone is hitting this API with weird params - like using curl to break it
	if( typeof body.username == undefined) {				// no username field
		extendedfailure = " missing first argument!";
		console.log(extendedfailure);						// don't tell them much in case they are trying to determine field names
		return false;
	}
	if( typeof body.password == undefined ) {				// no password field
		extendedfailure = " missing 2nd paramter!";
		console.log(extendedfailure);
		return false;
	}
	console.log("body.username = " + body.username);
	console.log("body.password = " + body.password);
	
	user = body.username.trim();						// extract the fields we want - remove leading and following spaces
	pw = body.password.trim();
	
	indx = findUser(user);								// find the index of this username in the storage
	console.log("indx = " + indx);
	console.log(" at that point: " + JSON.stringify(registeredUsers[indx]));
	
	if( indx === -1 ) {									// username not found in array
		extendedfailure = " invalid username";
		console.log(extendedfailure);
		return false;
	}
	if( checkPw(indx, pw) === false ) {					// check the input password with the stored hashed password for this user
		extendedfailure = " wrong password";
		console.log(extendedfailure);
		return false;
	}
	
	// if they get here, they matched username and password
	console.log ("username : " + user + " successfully logged in!");
	
	// use a limited time sessionID for this user
	sessionID = (Math.random()*100).toString(36).replace('.','');
	console.log("session id = " + sessionID);
	
	// save the current username in this case
	username = user;
	
	// time this sessionID out after 5 minutes, forcing them to log in again if authenticated function is called
	setTimeout( clearSessionID, 5*60*1000 );
	return true;
}

app.use( bodyparser.json() );							// use bodyparser to parse json data in POSTs

//
//	register - this function just associates a login and password, and stores the info in hashed format in local storage
//
app.post('/api/register', function (req, res) {
	console.log('received call to store password');	
	
	if (processRegisterUser(req.body) === false) {
		//console.log(extendedfailure);
		res.send(extendedfailure);
	} else {
		//	console.log(" password sent: " + req.body.password + "   stored as  " + pword);
		res.send('registered');					
	}
});

//
//	storekey - this function will store a public key from a registered user
//
app.post('/api/storekey', function (req, res) {
	console.log('received call to store a public key');	
	var results = processStoreKey(req.body);
	if( results === true) {
		res.send("Public Key successfully stored");
	} else {
		res.send("Problem encountered while trying to store public key. Try logging in again and trying again.");
	}						
});

//
//	login - this function will try to log a user in and return a session ID
//
app.post('/api/login', function (req, res) {
	console.log('received call to login');
	
	var results = processLogin(req.body);
	if( results === true) {
		res.send("login successful, use this sessionID for further API calls: " + sessionID);
	} else {
		res.send("login failed, try again");
	}
});

//
//	signedmessage - this function will take a username and message and look up the publickey and attempt to verify the signature
//
app.post('/api/signedmessage', function(req,res) {
	console.log('received call to process a signed message');
	var results = processSignedMessage(req.body);
	if( results === true) {
		res.send("Message: \n "  + req.body.message + "\n\nhas been verified using the user's publickey!");
	} else {
		res.send(extendedfailure);
	}
});


// run this listener on port 8000 (hope you have it open)
app.listen(8000, function() {
	console.log('Challenge server listening on port 8000');
});