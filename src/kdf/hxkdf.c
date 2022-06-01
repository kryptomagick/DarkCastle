void hxKDF(uint8_t *in, int inlen, unsigned char * kdfOut, int kdfOutLen, unsigned char * salt, int saltlen, int iterations) {
    struct hxState kdfState;
    hxInit(&kdfState);
    hxKeyApply256(&kdfState, salt);
    int blocksize = 64;
    uint8_t block[64] = {0};
    for (int i = 0; i < inlen; i++) {
        block[i] ^= in[i];
    }
    for (int i = 0; i < iterations; i++) {
        hxUpdate(&kdfState, block);
    }
    hxOutput(&kdfState);
    memcpy(kdfOut, kdfState.H256, 32*(sizeof(uint8_t)));
}
