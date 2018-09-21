# Bitpay code challenge
# REPO: David-2018

This repo contains the server and the client tester for the Bitpay code challenge.

The server runs with no command line options:
- node challenge_server.js

The client takes many command line options.  To see them, type:
- node challenge_client.js

The server implements the following API functions:
* Register a user (and securely save the password)
* Login a user
* Store a public key for an authenticated user
* Verify a signed message from any user that has stored a public key

Local storage was done in memory, not in any permanent storage database or files.
this means that the registered users will be lost if the server is stopped.

The way to test the basic functionality is to first register a username and password

- node challenge_client register username password

Then, the user must log in to be able to store a public key:

- node challenge_client login username password

If the username is found and the password matches, a sessionID will be returned. This is the authentication method.  this sessionID will timeout after 5 minutes for security reasons.

To store a public key:

- node challenge_client storepubkey sessionID
The public key is found in the file pub.pem under the ./pem directory.  Sample
public and private pem files were created using the openssl tool and included.

To sign a message, then send to the server for verification:

- node challenge_client signandsend username

The client will read the message from the message.txt file in the same directory. The username must be previously registered and public key previously stored.  However, the user does not need to be authenticated at this time.


The majority of the node modules needed are listed in the package-lock.json.  Run npm init to rebuild the node_modules folder correctly.

# Conclusion

This server is very limited in scope.  With additional time, I would have implemented the MongoDB storage, as well as cleaned up the client tester and allowed the user to not have to load keys from the drive or get the message from the filesystem.  Finally, I would have added monitoring to the API endpoints for calls that were coming in too rapidly (successive logins, for example).

Thank you for taking the time to look at this project.
