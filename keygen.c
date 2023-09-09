/*
 * Name: Karina Kallas
 * Course: CS344
 * Assignment: OTP
 * Due Date: June 11, 2023
 * General Description: Create five small programs that encrypt and decrypt using a one-time pad.
 * Sources: CS344 course material, man pages
 *
 * PROGRAM keygen.c DESCRIPTION: This program creates a key file of specified length. The characters in the
 * file generated will be any of the 27 allowed characters, generated using the standard Unix randomization methods.
 * Do not create spaces every five characters, as has been historically done. Note that you specifically do not
 * have to do any fancy random number generation: we’re not looking for cryptographically
 * secure random number generation. rand()Links to an external site. is just fine.
 * The last character keygen outputs should be a newline. Any error text must be output to stderr.
 *
 */

/**************************************
 *
 *          INCLUDE and CONSTANTS
 *
 *************************************/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char ALLOWED_ARRAY[27] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
        'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', ' '
};

/*********************************************
 *
 *                     MAIN
 *          - argument is length of key file
 *          - print key to stdout
 *
 ********************************************/

int main (int argc, char *argv[]) {
    /* Set up variables and check for errors. */
    int i, n;
    // Seed the random number generator with the current time
    srand(time(NULL));

    if (argc <= 1) {
        fprintf(stderr, "Need to include keygen length.\n");
        exit(1);
    } if (argc == 2) {
        n = atoi(argv[1]);  // Convert the argument to an integer
    }else{
        fprintf(stderr, "Too many arguments.\n");
        exit(1);
    }

    /* Select random numbers between 0-27 to index chars from ALLOWED_ARRAY and print to stdout.
     * n = length of key list of chars
     * \n will be printed once n chars have been printed */
    for( i = 0 ; i < n ; i++ ) {
        int index = rand() % 27;  // mod by 27
        printf("%c", ALLOWED_ARRAY[index]);
    }
    printf("%c", '\n');
    fflush(stdout);

    return(0);
}