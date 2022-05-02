#include <stdint.h>

uint64_t rotl64(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t rotr64(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

uint32_t rotl32(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t rotr32(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void capturePassphrase(unsigned char * passphrase) {
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);
    while (1) {
        printf("Enter passphrase:");
        //unsigned char * passphrase_primary[256];
        scanf("%s", passphrase);
        unsigned char * passphrase_confirm[256];
        printf("\nEnter passphrase again:");
        scanf("%s", passphrase_confirm);
        if (strcmp(passphrase, passphrase_confirm) != 0) {
            printf("Error: Passphrase mismatch\n");
        }
        else {
            printf("\nGenerating keys...this may take a while...\n");
            break;
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &save);
}
