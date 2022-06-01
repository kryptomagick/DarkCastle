#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int keywrap128_ivlen = 16;
int keywrap256_ivlen = 16;
int keywrap512_ivlen = 16;
int keywrap1024_ivlen = 16;

void key_wrap_encrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * K, unsigned char * nonce) {
    if (key_length == 32) {
        getRandomBytes(keyprime, key_length);
        getRandomBytes(nonce, keywrap256_ivlen);
        memcpy(K, keyprime, key_length);
        uvajda1_crypt(K, key, nonce, key_length);
        for (int i = 0; i < key_length; i++) {
            K[i] = K[i] ^ key[i];
        }
    }
}

void key_wrap_decrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * nonce) {
    if (key_length == 32) {
        for (int i = 0; i < key_length; i++) {
            keyprime[i] = keyprime[i] ^ key[i];
        }
        uvajda1_crypt(keyprime, key, nonce, key_length);
    }
}
