# Messenger
The project consists of two major parts.
1. Creation of RSA encryption keys.
 - Uses custom prime number generation logic to create a unique p and q to be used in keyGen.
 - The prime number generation utilizes a Parallel.For loop to generate a prime number of a given number of bits (I used 32 bits most of the time)
 - Once the p and q have been generated, keyGen will create Base64 encoded public and private encryption keys and store them as json in the working directory.

2. Interaction with webserver.
 - The program then lets you choose how to interact with the server, you have 4 basic options as follows
   - sendKey: this will upload your public key in json form to the webserver so that other users can encrypt messages to send to you.
   - getKey: this will retrieve the public key for a given user from the webserver.
   - sendMsg: this allows you to encrypt a message with another user's public key and send it to them on the server.
   - getMsg: this retrieves a message for you from the server and decrypts it using your private key.
