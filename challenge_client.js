//------------------------------------------------------------
//
//	challenge_client.js
//
//	Author: David Gentry
//	Date: 9/21/2018
//
//	Test the server
//
//  to see the parameters, use this command line:
//	   node challenge_client.js
//
// 	   for the storing of the public key, the pub.pem file in the pem folder is used
//     same for the private key to sign the message
//	   the message to be signed is in the message.txt file
//------------------------------------------------------------
'use strict'

var http = require('http');
var crypto = require('crypto');
var fs = require('fs');

var command = '';
var params = [];

const private_key = fs.readFileSync('pem/priv.pem', 'utf-8')
const public_key = fs.readFileSync('pem/pub.pem', 'utf-8')
const message = fs.readFileSync('message.txt', 'utf-8')

// make sure they sent a command of some kind.
if( getArgs() === false ) {
	console.log("\ntry again");
} else {
	console.log("finished");
}


function remove_newlines( inp ) {
	var outp = [];
	var j = 0;
	
	for (var i=0; i<inp.length; i++ ){
		if( inp[i] !== '\n' ) {
			outp.push(inp[i]);
		}
	}
	return outp.toString();
}
function getArgs() {
	var item = '';
	var arrLen = process.argv.length;
	var success = false;

	// process.argv, index 0 = node, index 1 = scriptname, 2 = command, 3... = params

	if( arrLen < 3 ) {
		console.log("\n\nUSAGE:  node challenge_client.js  <command> <arg1> <arg2> etc");
		console.log("    commands: ");
		console.log("       register <username> <password> - this will save the username and password as the single registered user");
		console.log("       login <username> <password>  - this will return a sessionID string to use for the remaining calls to be authenticated");
		console.log("       storepubkey <pubkey> <sessionID> - pubkey to store, sessionID from login call");
		console.log("       signandsend <username> <privkey> '<message>' - sign 'message' with private key");
		success = false;
	} else {
		command = process.argv[2]
		
		switch(command) {
			case 'register':
				if( process.argv.length < 5) {
					console.log("register command, but missing some arguments:    register <username> <password>");
					success = false;
					break;
				}
				params = [];
				params[0] = process.argv[3];
				params[1] = process.argv[4];
				console.log("calling register with these params: username = " + params[0] + ", password = " + params[1] );
				processRegisterCall();
				success = true;
				break;
			case 'storepubkey':
				if( process.argv.length < 4) {
					console.log("register command, but missing some arguments:    storepubkey <sessionID>");
					success = false;
					break;
				}
				params = [];
				params[0] = public_key.replace(/(\r\n|\n|\r)/gm,"");					
				params[1] = process.argv[3];
				processStoreKeyCall();
				success = true;
				break;
			case 'signandsend':
				if( process.argv.length < 4) {
					console.log("signandsend command, but missing some arguments:    signandsend <username> <privkey> '<message>'");
					success = false;
					break;
				}
				params = [];
				params[0] = process.argv[3];	// username
				params[1] = private_key;		// from ./pem/pub.pem
				params[2] = message;			// from ./message.txt
				processSignAndSend();	
				success = true;
				break;
			case 'login':
				if( process.argv.length < 5) {
					console.log("login command, but missing some arguments:    login <username> <password>");
					success = false;
					break;
				}
				params = [];
				params[0] = process.argv[3];
				params[1] = process.argv[4];
				console.log("calling login with these params: username = " + params[0] + ", password = " + params[1] );
				processLoginCall();	
				success = true;
				break;

			default: 
				console.log("Unknown command: " + command);
				break;
		}
	}
	return success;
}

function processSignAndSend() {
	var post_data = '';
	var signature, signature_hex;
	var signagent = crypto.createSign('sha256');
	
	
	// update the input with the message to sign
	signagent.update( params[2] );
	signagent.end();
	
	
	// create the signature
	
	signature = signagent.sign( params[1] );
	
	signature_hex = signature.toString('hex');
	console.log('signature: ' + signature + '     hex = ' + signature_hex);
	
	
	// call the API now with these items as the data - we DO NOT send the private key, just the username, message and signature
	post_data = '{"username":"' + params[0] + '","message":"' + params[2] + '","signature":"' + signature_hex + '"}';
	//console.log("sending:  " + post_data);
	processAPICall(post_data, 'signedmessage');
}

function processLoginCall() {
		var post_data = '{"username":"' + params[0] + '","password":"' + params[1] +'"}';
		processAPICall(post_data, 'login');
}

function processRegisterCall() {
	
	var	post_data = '{"username":"' + params[0] + '","password":"' + params[1] +'"}';
	processAPICall( post_data, 'register');
}

function processStoreKeyCall() {
	var	post_data = '{"pubkey":"' + params[0] + '","sessID":"' + params[1] +'"}';
	console.log("sending:  " + post_data);
	processAPICall( post_data, 'storekey');
}

function processAPICall(data, endpoint) {
	var post_req  = null,
		post_data = data;

	var post_options = {
		hostname: '127.0.0.1',
		port    : '8000',
		path    : '/api/' + endpoint,
		method  : 'POST',
		headers : {
			'Content-Type': 'application/json',
			'Cache-Control': 'no-cache',
			'Content-Length': post_data.length
		}
    };

	post_req = http.request(post_options, function (res) {
		//console.log('STATUS: ' + res.statusCode);
		//console.log('HEADERS: ' + JSON.stringify(res.headers));
		res.setEncoding('utf8');
		res.on('data', function (chunk) {
			console.log('Response: ', chunk);
		});
	});

	post_req.on('error', function(e) {
		console.log('problem with request: ' + e.message);
	});

	post_req.write(post_data);
	post_req.end();
}
