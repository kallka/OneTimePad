/*
 * Name: Karina Kallas
 * Course: CS344
 * Assignment: OTP
 * Due Date: June 11, 2023
 * General Description: Create five small programs that encrypt and decrypt using a one-time pad.
 * Sources: CS344 course material, man pages
 *
 * PROGRAM enc_client.c DESCRIPTION: Client encoding program. Reads message from client and sends
 * to enc_server to encode.
 *
 */


/**************************************
 *
 *          INCLUDE and DEFINE
 *          CONSTANTS
 *
 *************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

#define MAX_BUFFER_SIZE 100000

char sharedKey[] = "enckey";
FILE* filepointer;
FILE* keypointer;


/*********************************************
 *
 *                  HELPER FUNCTIONS
 *                  - cleanup, error, verifyOK
 *                  - struct set up
 *
 *
 ********************************************/

// Clean Up
void cleanup() {
    if (filepointer != NULL) {
        fclose(filepointer);
    }
    if (keypointer != NULL) {
        fclose(keypointer);
    }
}

// Error function used for reporting issues
void error(const char *msg, int i) {
    fprintf(stderr, "%s", msg);
    exit(i);
}

void verifyOK(char* filep, size_t filelen, size_t keylen) {
    // Is key long enough?
    if (keylen < filelen) {
        error("Error: Key not long enough.\n", 1);
    }

    // Are all chars valid?
    int isValid = 1; // Flag to track if all chars are within the desired ASCII range 32, 65-90
    long int i;

    for (i = 0; i < filelen-1; i++) {
        char ch = filep[i];
        if ((int)ch == 0) {
            fprintf(stderr, "Problem is ZERO -> char = %d stored at index %ld \n", (int)ch, i);
            continue;
        }
        if (ch != 32 && (ch < 65 || ch > 90)) {
            isValid = 0;
            break; // Invalid char, exit loop
        }
    }

    if (isValid == 0) {
        error("Invalid characters in plaintext file.\n", 1);
    }
}

// Send a file to the socket - returns 1 if successful
int sendToSocket(int socketFD, char* fileBuffer, size_t lengthfile) {
    size_t totalCharsWritten = 0;
    while (totalCharsWritten < lengthfile) {
        ssize_t charsWritten = send(socketFD, fileBuffer + totalCharsWritten, lengthfile - totalCharsWritten, 0);
        if (charsWritten < 0) {
            error("CLIENT: ERROR writing file to socket\n", 2);
        }
        if (charsWritten == 0) {
            // Handle the case where no bytes were written (possibly due to a closed connection)
            error("ERROR: No data written to socket.\n", 2);
        }
        totalCharsWritten += charsWritten;
    }

    if (totalCharsWritten < lengthfile) {
        error("CLIENT: WARNING: Not all data written to socket!\n", 2);
    }

    return 0;  // Return success status
}

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portNumber)
{
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;

    // Store the port number - convert host byte to network byte order
    address->sin_port = htons(portNumber);
}


/*********************************************
 *
 *                     MAIN
 *
 *
 ********************************************/
int main(int argc, char *argv[]) {
    ///* CHECK ARGS *///
    if (argc != 4) {
        fprintf(stderr,"USAGE: %s hostname port\n", argv[3]);
        exit(-1);
    }

    ///* READ KEY AND FILE CONTENTS INTO BUFFERS AND VERIFY *///
    // Open files
    filepointer = fopen(argv[1], "r");
    if (filepointer == NULL) {error("Error opening file to encode.\n", 1);}
    keypointer = fopen(argv[2], "r");
    if (keypointer == NULL) {error("Error opening key.\n", 1);}

    // Register the cleanup
    atexit(cleanup);

    // Read file contents into buffer
    char fileBuffer[MAX_BUFFER_SIZE];
    memset(fileBuffer, '\0', sizeof(fileBuffer));
    size_t lengthfile = fread(fileBuffer, 1, sizeof(fileBuffer), filepointer);
    if (lengthfile == 0) {
        error("Error reading file.\n", 1);
    }
    //fprintf(stderr, "file length: %zu\n", lengthfile);
    //fileBuffer[lengthfile] = '\0';

    // Read key contents into buffer
    char keyBuffer[MAX_BUFFER_SIZE];
    memset(keyBuffer, '\0', sizeof(keyBuffer));
    size_t lengthkey = fread(keyBuffer, 1, sizeof(keyBuffer), keypointer);
    if (lengthkey == 0) {
        error("Error reading key.\n", 1);
    }
    //keyBuffer[lengthkey] = '\0';

    // Verify length and contents of file and key
    verifyOK(fileBuffer, lengthfile, lengthkey);

    ///* CREATE SOCKET *///
    int socketFD;
    struct sockaddr_in serverAddress;

    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0){
        error("CLIENT: ERROR opening socket\n", 2);
    }

    // Set up the server address struct - 3rd arg will always be port
    setupAddressStruct(&serverAddress, atoi(argv[3]));

    // Connect to server
    if (connect(socketFD, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0){
        error("CLIENT: ERROR connecting\n", 2);
    }


    ///* SEND TO SOCKET *///
    //MESSAGE 1: Shared Key
    sendToSocket(socketFD, sharedKey, strlen(sharedKey));

    // Wait for the confirmation from the client
    char confirmation[100];
    ssize_t bytesRead = recv(socketFD, confirmation, sizeof(confirmation) - 1, 0);
    if (bytesRead < 0) {
        perror("Error reading confirmation from client");
        exit(1);
    }
    confirmation[bytesRead] = '\0';
    // Process the confirmation or send another message
    if (strcmp(confirmation, "ok") == 0) {
        // Send another message
        // MESSAGES 2: Send file
        sendToSocket(socketFD, fileBuffer, lengthfile+1);
    }else {
        error("Incorrect server.\n", 2);
    }


    // MESSAGES 3: Send key size and key
    bytesRead = recv(socketFD, confirmation, sizeof(confirmation) - 1, 0);
    if (bytesRead < 0) {
        perror("Error reading confirmation from client");
        exit(1);
    }
    confirmation[bytesRead] = '\0';
    // Process the confirmation or send another message
    if (strcmp(confirmation, "ok") == 0) {
        // Send another message
        // MESSAGES 3: Send key
        sendToSocket(socketFD, keyBuffer, lengthkey+1);
    }


    // Clean up fileBuffer and keyBuffer
    memset(fileBuffer, '\0', sizeof(fileBuffer));
    memset(keyBuffer, '\0', sizeof(keyBuffer));


    ///* READ FROM SOCKET *///
    // Read data from the socket, leaving \0 at end
    size_t charsRead = recv(socketFD, fileBuffer, sizeof(fileBuffer) - 1, 0);
    if (charsRead < 0){
        error("CLIENT: ERROR reading from socket\n", 2);
    }
    fileBuffer[charsRead-1] = '\0';
    printf("%s", fileBuffer);
    //printf("\n");
    fflush(stdout);

    // Close the socket
    close(socketFD);
    return 0;
}
