/*
 * Name: Karina Kallas
 * Course: CS344
 * Assignment: OTP
 * Due Date: June 11, 2023
 * General Description: Create five small programs that encrypt and decrypt using a one-time pad.
 * Sources: CS344 course material, man pages, @cs344/8_3_server.c
 *
 * PROGRAM enc_server.c DESCRIPTION: Encryption server runs in the background as daemon.
 *          1.) Perform the actual encoding using a file from enc_client and a keygen.
 *          2.) Listen on a particular port/socket, specified when it is first run.
 *          3.) Output an error if it cannot be run due to a network error, such as the ports being unavailable.
 *          4.) When a connection is made, enc_server must call accept to generate the socket used for actual
 *              communication, and then use a separate process to handle the rest of the servicing for this
 *              client connection (see below), which will occur on the newly accepted socket.
 *          5.) This child process of enc_server must first check to make sure it is communicating with enc_client.
 *          6.) After verifying that the connection to enc_server is coming from enc_client, then this child receives
 *              plaintext and a key from enc_client via the connected socket.
 *          7.) The enc_server child will then write back the ciphertext to the enc_client process that it is
 *              connected to via the same connected socket.
 *          8.) Note that the key passed in must be at least as big as the plaintext.
 *          9.) Your version of enc_server must support up to five concurrent socket connections.
 *
 * Call to initilaize enc_server: $ enc_server 57171 &
 *
 */


/**************************************
 *
 *          INCLUDE, DEFINE,
 *          and CONSTANTS
 *
 *************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_BUFFER_SIZE 100000

char sharedKey[] = "deckey";
const char ALLOWED_ARRAY[27] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
        'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', ' '
};

/*********************************************
 *
 *                  HELPER FUNCTIONS
 *                  - error
 *                  - struct set up
 *
 *
 ********************************************/
// Error function used for reporting issues
void error(const char *msg) {
    fprintf(stderr, "%s", msg);
    exit(1);
}

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, int portNumber) {

    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number - convert host order to network order with htons
    address->sin_port = htons(portNumber);
    // Allow a client at any address to connect to this server
    address->sin_addr.s_addr = INADDR_ANY;
}

// Decode file with key
char* decodeFile(char* file, const char* key, long int len) {
    int fileval;
    int keyval;
    int returnval;
    long int i;
    for (i = 0; i < len-1; i++) {
        // Find correct vals in ALLOWED ARRAY
        fileval = (int)file[i] - 65 ;
        keyval = (int)key[i] - 65;
        // Check for space
        if (fileval < 0 ) { fileval = 26; }
        if (keyval < 0 ) { keyval = 26; }
        // Save new char
        returnval = (fileval - keyval + 27) % 27; // subtract cipher - key
        file[i] = ALLOWED_ARRAY[returnval];
    }
    file[i] ='\0';

    return file;
}

/*********************************************
 *
 *                   HANDLE CLIENT
 *          1. Check that connected to enc_client
 *          2. Read from socket to buffer
 *          3. Encrypt data if key large enough
 *          4. Return encrypted message
 *
 ********************************************/
void handleClient(connectionSocket){
    const char* confirmation = "ok";
    const char* stop = "no";
    char receivedKey[8];
    char fileBuffer[MAX_BUFFER_SIZE];
    char keyBuffer[MAX_BUFFER_SIZE];
    memset(fileBuffer, '\0', sizeof(fileBuffer));
    memset(keyBuffer, '\0', sizeof(keyBuffer));

    /// MESSAGE 1: VERIFY SHARED KEY
    // Read sharedKey from buffer
    ssize_t bytesRead = recv(connectionSocket, receivedKey, 6, 0);
    if (bytesRead < 0) {
        error("ERROR reading from socket.\n");
    }
    receivedKey[bytesRead] = '\0';

    //compare keys
    if (strcmp(receivedKey, sharedKey) != 0)  {
        // Invalid shared key, close the connection
        //error("Error: keys do not match.\n");
        //SEND NOT OK
        send(connectionSocket, stop, strlen(stop), 0);
        goto closeChild;
    } else {
        //SEND OK
        send(connectionSocket, confirmation, strlen(confirmation), 0);
    }

    /// MESSAGE 2: GET THE FILE TO DECODE
    // Read File from buffer
    size_t fileSizeRead = 0;
    bytesRead = 0;
    while (fileSizeRead < MAX_BUFFER_SIZE - 1) {
        bytesRead = recv(connectionSocket, fileBuffer + fileSizeRead, 1, 0);

        if (bytesRead < 0) {
            error("Error reading File message.\n");
        } else if (bytesRead == 0) {
            // Connection closed before finding the null terminator
            break;
        }
        fileSizeRead += bytesRead;

        if (fileBuffer[fileSizeRead - 1] == '\0') {
            // Found the null terminator, end of data
            break;
        }
    }
    fileBuffer[fileSizeRead] = '\0';
    //SEND OK
    send(connectionSocket, confirmation, strlen(confirmation), 0);

    /// MESSAGE 3: GET THE KEY FOR ENCODING
    // Read Key from buffer
    size_t keySizeRead = 0;
    bytesRead = 0;
    while (keySizeRead < MAX_BUFFER_SIZE - 1) {
        bytesRead = recv(connectionSocket, keyBuffer + keySizeRead, 1, 0);

        if (bytesRead < 0) {
            error("Error reading Key message.\n");
        } else if (bytesRead == 0) {
            // Connection closed before finding the null terminator
            break;
        }
        keySizeRead += bytesRead;

        if (keyBuffer[keySizeRead - 1] == '\0') {
            // Found the null terminator, end of data
            break;
        }
    }
    keyBuffer[keySizeRead] = '\0';

    /// ENCODE
    decodeFile(fileBuffer, keyBuffer, fileSizeRead);

    // Send response to client
    //const char *response = "Server response: Thank you for the messages!";
    size_t n = send(connectionSocket, fileBuffer, fileSizeRead, 0);
    if (n < 0) {
        error("ERROR writing to socket");
    }
    closeChild:
    close(connectionSocket);
}

/**********************************************************
 *
 *                     MAIN
 *              1. Set up listenSocket (main welcome socket)
 *              2. Listen for up to 5 connections
 *              3. Create child process to handle client sockets
 *
 *********************************************************/
int main(int argc, char *argv[]){
    ///* SOCKET VARIABLES *///
    int listenSocket, connectionSocket;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);


    ///* CHECK ARGS *///
    if (argc != 2) {
        fprintf(stderr,"USAGE ERROR: %s port\n", argv[0]);
        exit(1);
    }

    ///* CREATE LISTEN SOCKET *///
    // Create the socket that will listen for connections
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        error("ERROR on opening socket.");
    }

    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));

    // Associate the socket to the port
    if (bind(listenSocket,
             (struct sockaddr *)&serverAddress,
             sizeof(serverAddress)) < 0){
        error("ERROR on binding.");
    }

    // Start listening for connections. Allow up to 5 connections to queue up
    if (listen(listenSocket, 5) <0) {
        error("ERROR on listen.");
    }

    // Accept a connection, blocking if one is not available until one connects
    while(1){
        // Accept the connection request which creates a connection socket
        connectionSocket = accept(listenSocket,
                                  (struct sockaddr *)&clientAddress,
                                  &sizeOfClientInfo);
        if (connectionSocket < 0){
            error("ERROR while accepting client socket.\n");
        }

        ///* FORK AND HANDLE EACH CLIENT *///
        // Fork a child process to handle new client socket
        pid_t child_pid = fork();
        // Child process
        if (child_pid == 0) {
            close(listenSocket);
            handleClient(connectionSocket);
            // Parent Process
        } else if (child_pid > 0) {
            // Check if any child processes have terminated
            int child_status;
            pid_t terminated_child;
            while ((terminated_child = waitpid(-1, &child_status, WNOHANG)) > 0) {
                if (WIFEXITED(child_status)) {
                    // Child process terminated normally - save exit_status in case need for later
                    int exit_status = WEXITSTATUS(child_status);
                } else if (WIFSIGNALED(child_status)) {
                    // Child process terminated due to a signal - save signal_number in case need for later
                    int signal_number = WTERMSIG(child_status);
                    // Handle the signal number as needed
                    error("Child process %d terminated due to signal.");
                }
            }
        } else {
            error("ERROR on forking child process.\n");
        }

    }  // END forever loop for listeningSocket

    // Close the listening socket
    close(listenSocket);
    return 0;
}
