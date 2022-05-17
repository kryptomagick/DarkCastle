#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* KryptoMagick Tp St Cipher (Tep Set) */

uint32_t tpstC0[8] = {0xb77591cd, 0xda867abc, 0xae44c63f, 0xe5eda92e, 0xec8a2973, 0xca320d7d, 0xda6dd8f7, 0x8640acef};

struct tpstState {
    uint32_t K[48][8];
    uint32_t M[8];
    uint32_t last[8];
    uint32_t next[8];
    int rounds;
};

struct tpstKSAState {
    uint32_t r[16];
};

void tpstKSF(struct tpstState *state, struct tpstKSAState *KSstate) {
    int r, i;
    uint32_t tmp1[16] = {0};
    state->K[0][0] = KSstate->r[0];
    state->K[0][1] = KSstate->r[1];
    state->K[0][2] = KSstate->r[2];
    state->K[0][3] = KSstate->r[3];
    state->K[0][4] = KSstate->r[4];
    state->K[0][5] = KSstate->r[5];
    state->K[0][6] = KSstate->r[6];
    state->K[0][7] = KSstate->r[7];
    for (r = 1; r < state->rounds; r++) {
        for (i = 0; i < 16; i++) {
            KSstate->r[i] += (rotl32(KSstate->r[(i + 1) & 0xF], 21) + state->K[(r - 1) % state->rounds][i & 0x07]);
            state->K[r][i & 0x07] += (KSstate->r[i] + tmp1[i] ^ (rotr32(tmp1[i], 10) ^ rotl32(KSstate->r[i], 21)));
            tmp1[i] += state->K[r][i & 0x07];
        }
    }
}

void tpstGenSubKeys(struct tpstState * state, unsigned char * key, int keylen) {
    struct tpstKSAState kstate;
    int c = 0;
    int i;
    int s;
    state->rounds = 48;
    memset(state->K, 0, state->rounds*(8*sizeof(uint32_t)));
    memset(kstate.r, 0, 16*sizeof(uint32_t));
    memset(state->last, 0, 8*sizeof(uint32_t));
    memset(state->next, 0, 8*sizeof(uint32_t));

    for (i = 0; i < (keylen / 4); i++) {
        kstate.r[i] = (((uint32_t)key[c] << 24) + ((uint32_t)key[c+1] << 16) + ((uint32_t)key[c+2] << 8) + (uint32_t)key[c+3]);
        c += 4;
    }
    kstate.r[8] += tpstC0[0];
    kstate.r[9] += tpstC0[1];
    kstate.r[10] += tpstC0[2];
    kstate.r[11] += tpstC0[3];
    kstate.r[12] += tpstC0[4];
    kstate.r[13] += tpstC0[5];
    kstate.r[14] += tpstC0[6];
    kstate.r[15] += tpstC0[7];
    tpstKSF(state, &kstate);
}

void tpstLoadBlock(struct tpstState *state, uint8_t *block) {
    state->M[0] = ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->M[1] = ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->M[2] = ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->M[3] = ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
    state->M[4] = ((block[16] << 24) + (block[17] << 16) + (block[18] << 8) + block[19]);
    state->M[5] = ((block[20] << 24) + (block[21] << 16) + (block[22] << 8) + block[23]);
    state->M[6] = ((block[24] << 24) + (block[25] << 16) + (block[26] << 8) + block[27]);
    state->M[7] = ((block[28] << 24) + (block[29] << 16) + (block[30] << 8) + block[31]);
}

void tpstUnloadBlock(struct tpstState *state, uint8_t *block) {
    block[0] = ((state->M[0] & 0xFF000000) >> 24);
    block[1] = ((state->M[0] & 0x00FF0000) >> 16);
    block[2] = ((state->M[0] & 0x0000FF00) >> 8);
    block[3] = ((state->M[0] & 0x000000FF));
    block[4] = ((state->M[1] & 0xFF000000) >> 24);
    block[5] = ((state->M[1] & 0x00FF0000) >> 16);
    block[6] = ((state->M[1] & 0x0000FF00) >> 8);
    block[7] = ((state->M[1] & 0x000000FF));
    block[8] = ((state->M[2] & 0xFF000000) >> 24);
    block[9] = ((state->M[2] & 0x00FF0000) >> 16);
    block[10] = ((state->M[2] & 0x0000FF00) >> 8);
    block[11] = ((state->M[2] & 0x000000FF));
    block[12] = ((state->M[3] & 0xFF000000) >> 24);
    block[13] = ((state->M[3] & 0x00FF0000) >> 16);
    block[14] = ((state->M[3] & 0x0000FF00) >> 8);
    block[15] = ((state->M[3] & 0x000000FF));
    block[16] = ((state->M[4] & 0xFF000000) >> 24);
    block[17] = ((state->M[4] & 0x00FF0000) >> 16);
    block[18] = ((state->M[4] & 0x0000FF00) >> 8);
    block[19] = ((state->M[4] & 0x000000FF));
    block[20] = ((state->M[5] & 0xFF000000) >> 24);
    block[21] = ((state->M[5] & 0x00FF0000) >> 16);
    block[22] = ((state->M[5] & 0x0000FF00) >> 8);
    block[23] = ((state->M[5] & 0x000000FF));
    block[24] = ((state->M[6] & 0xFF000000) >> 24);
    block[25] = ((state->M[6] & 0x00FF0000) >> 16);
    block[26] = ((state->M[6] & 0x0000FF00) >> 8);
    block[27] = ((state->M[6] & 0x000000FF));
    block[28] = ((state->M[7] & 0xFF000000) >> 24);
    block[29] = ((state->M[7] & 0x00FF0000) >> 16);
    block[30] = ((state->M[7] & 0x0000FF00) >> 8);
    block[31] = ((state->M[7] & 0x000000FF));
}

void tpstSubBlock(struct tpstState *state) {
    state->M[0] += state->M[1];
    state->M[1] += state->M[2];
    state->M[2] += state->M[3];
    state->M[3] += state->M[4];
    state->M[4] += state->M[5];
    state->M[5] += state->M[6];
    state->M[6] += state->M[7];
    state->M[7] += state->M[0];
}

void tpstInvSubBlock(struct tpstState *state) {
    state->M[7] -= state->M[0];
    state->M[6] -= state->M[7];
    state->M[5] -= state->M[6];
    state->M[4] -= state->M[5];
    state->M[3] -= state->M[4];
    state->M[2] -= state->M[3];
    state->M[1] -= state->M[2];
    state->M[0] -= state->M[1];
}

void tpstRotateLeft(struct tpstState *state) {
    uint32_t tmp;
    tmp = state->M[1];
    state->M[1] = state->M[0];
    state->M[0] = tmp;

    tmp = state->M[1];
    state->M[1] = state->M[2];
    state->M[2] = tmp;
    
    tmp = state->M[3];
    state->M[3] = state->M[2];
    state->M[2] = tmp;

    tmp = state->M[4];
    state->M[4] = state->M[3];
    state->M[3] = tmp;

    tmp = state->M[5];
    state->M[5] = state->M[4];
    state->M[4] = tmp;

    tmp = state->M[6];
    state->M[6] = state->M[5];
    state->M[5] = tmp;

    tmp = state->M[7];
    state->M[7] = state->M[6];
    state->M[6] = tmp;
}

void tpstRotateRight(struct tpstState *state) {
    uint32_t tmp;
    tmp = state->M[7];
    state->M[7] = state->M[6];
    state->M[6] = tmp;

    tmp = state->M[6];
    state->M[6] = state->M[5];
    state->M[5] = tmp;

    tmp = state->M[5];
    state->M[5] = state->M[4];
    state->M[4] = tmp;

    tmp = state->M[4];
    state->M[4] = state->M[3];
    state->M[3] = tmp;

    tmp = state->M[3];
    state->M[3] = state->M[2];
    state->M[2] = tmp;

    tmp = state->M[2];
    state->M[2] = state->M[1];
    state->M[1] = tmp;
    
    tmp = state->M[1];
    state->M[1] = state->M[0];
    state->M[0] = tmp;
}

void tpstMixBlock(struct tpstState *state) {
    state->M[0] += state->M[1];
    state->M[2] += state->M[0];
    state->M[1] += state->M[3];
    state->M[3] += state->M[2];

    state->M[1] = rotl32(state->M[1], 21);
    state->M[3] = rotl32(state->M[3], 6);
    state->M[4] = rotr32(state->M[4], 10);
    state->M[6] = rotr32(state->M[6], 3);

    state->M[4] += state->M[5];
    state->M[6] += state->M[4];
    state->M[5] += state->M[7];
    state->M[7] += state->M[6];

    state->M[0] += state->M[6];
    state->M[1] += state->M[7];
    state->M[2] += state->M[4];
    state->M[3] += state->M[5];

    state->M[4] += state->M[2];
    state->M[5] += state->M[3];
    state->M[6] += state->M[0];
    state->M[7] += state->M[1];
}

void tpstInvMixBlock(struct tpstState *state) {
    state->M[7] -= state->M[1];
    state->M[6] -= state->M[0];
    state->M[5] -= state->M[3];
    state->M[4] -= state->M[2];

    state->M[3] -= state->M[5];
    state->M[2] -= state->M[4];
    state->M[1] -= state->M[7];
    state->M[0] -= state->M[6];

    state->M[7] -= state->M[6];
    state->M[5] -= state->M[7];
    state->M[6] -= state->M[4];
    state->M[4] -= state->M[5];
    
    state->M[6] = rotl32(state->M[6], 3);
    state->M[4] = rotl32(state->M[4], 10);
    state->M[3] = rotr32(state->M[3], 6);
    state->M[1] = rotr32(state->M[1], 21);

    state->M[3] -= state->M[2];
    state->M[1] -= state->M[3];
    state->M[2] -= state->M[0];
    state->M[0] -= state->M[1];
}

void tpstAddRoundKey(struct tpstState *state, int round) {
    state->M[0] ^= state->K[round][0];
    state->M[1] ^= state->K[round][1];
    state->M[2] ^= state->K[round][2];
    state->M[3] ^= state->K[round][3];
    state->M[4] ^= state->K[round][4];
    state->M[5] ^= state->K[round][5];
    state->M[6] ^= state->K[round][6];
    state->M[7] ^= state->K[round][7];
}

void tpstBlockEncrypt(struct tpstState * state) {
    for (int r = 0; r < state->rounds; r++) {
        tpstSubBlock(state);
        tpstRotateLeft(state);
        tpstMixBlock(state);
        tpstAddRoundKey(state, r);
    }
}

void tpstBlockDecrypt(struct tpstState * state) {
    for (int r = (state->rounds - 1); r != -1; r--) {
        tpstAddRoundKey(state, r);
        tpstInvMixBlock(state);
        tpstRotateRight(state);
        tpstInvSubBlock(state);
    }
}

void tpstCBCEncrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &Sctx);
    load_pkfile(keyfile1, &ctx);
    unsigned char *password[password_len];
    amagus_random(password, password_len);
    BIGNUM *tmp;
    BIGNUM *BNctxt;
    BIGNUM *S;
    tmp = BN_new();
    BNctxt = BN_new();
    S = BN_new();
    unsigned char *X[mask_bytes];
    unsigned char *Y[mask_bytes];
    amagus_random(Y, mask_bytes);
    mypad_encrypt(password, password_len, X, mask_bytes, Y);
    BN_bin2bn(X, mask_bytes, tmp);
    cloak(&ctx, BNctxt, tmp);
    sign(&Sctx, S, BNctxt);
    int ctxtbytes = BN_num_bytes(BNctxt);
    unsigned char *password_ctxt[ctxtbytes];
    BN_bn2bin(BNctxt, password_ctxt);
    int Sbytes = BN_num_bytes(S);
    unsigned char *sign_ctxt[Sbytes];
    BN_bn2bin(S, sign_ctxt);
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    amagus_random(&iv, nonce_length);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, password_len, key, key_length, kdf_salt, salt_len, kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    int datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(password_ctxt, 1, mask_bytes, outfile);
    fwrite(Y, 1, mask_bytes, outfile);
    fwrite(sign_ctxt, 1, Sbytes, outfile);
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(iv, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);

    struct tpstState state;
    uint8_t block[32] = {0};
    int blocksize = 32;
    int blocks = datalen / bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    int extra = datalen % bufsize;
    int v = blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
        bufsize = extra;
    }
    int c = 0;
    int b;
    int i;
    tpstGenSubKeys(&state, keyprime, key_length);
    state.last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
    state.last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
    state.last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
    state.last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
    state.last[4] = ((iv[16] << 24) + (iv[17] << 16) + (iv[18] << 8) + iv[19]);
    state.last[5] = ((iv[20] << 24) + (iv[21] << 16) + (iv[22] << 8) + iv[23]);
    state.last[6] = ((iv[24] << 24) + (iv[25] << 16) + (iv[26] << 8) + iv[27]);
    state.last[7] = ((iv[28] << 24) + (iv[29] << 16) + (iv[30] << 8) + iv[31]);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
	if ((i == (blocks - 1)) && (extra != 0)) {
            for (int p = 0; p < extrabytes; p++) {
                buffer[(bufsize+extrabytes-1)-p] = (unsigned char *)extrabytes;
	    }
            bufsize = bufsize + extrabytes;
	}
        int bblocks = bufsize / blocksize;
        int bextra = bufsize % blocksize;
        if (bextra != 0) {
            bblocks += 1;
        }
        if (bufsize < blocksize) {
            bblocks = 1;
        }
        for (b = 0; b < bblocks; b++) {
	/*    if ((i == (blocks - 1)) && (extra != 0)) {
                for (int p = 0; p < extrabytes; p++) {
                    buffer[(bufsize-1)-p] = (unsigned char *)extrabytes;
	        }
	    } */
            block[0] = buffer[c];
            block[1] = buffer[c+1];
            block[2] = buffer[c+2];
            block[3] = buffer[c+3];
            block[4] = buffer[c+4];
            block[5] = buffer[c+5];
            block[6] = buffer[c+6];
            block[7] = buffer[c+7];
            block[8] = buffer[c+8];
            block[9] = buffer[c+9];
            block[10] = buffer[c+10];
            block[11] = buffer[c+11];
            block[12] = buffer[c+12];
            block[13] = buffer[c+13];
            block[14] = buffer[c+14];
            block[15] = buffer[c+15];
            block[16] = buffer[c+16];
            block[17] = buffer[c+17];
            block[18] = buffer[c+18];
            block[19] = buffer[c+19];
            block[20] = buffer[c+20];
            block[21] = buffer[c+21];
            block[22] = buffer[c+22];
            block[23] = buffer[c+23];
            block[24] = buffer[c+24];
            block[25] = buffer[c+25];
            block[26] = buffer[c+26];
            block[27] = buffer[c+27];
            block[28] = buffer[c+28];
            block[29] = buffer[c+29];
            block[30] = buffer[c+30];
            block[31] = buffer[c+31];
            tpstLoadBlock(&state, block);
	 
	    state.M[0] ^= state.last[0];
	    state.M[1] ^= state.last[1];
	    state.M[2] ^= state.last[2];
	    state.M[3] ^= state.last[3];
	    state.M[4] ^= state.last[4];
	    state.M[5] ^= state.last[5];
	    state.M[6] ^= state.last[6];
	    state.M[7] ^= state.last[7];

            tpstBlockEncrypt(&state);

	    state.last[0] = state.M[0];
	    state.last[1] = state.M[1];
	    state.last[2] = state.M[2];
	    state.last[3] = state.M[3];
	    state.last[4] = state.M[4];
	    state.last[5] = state.M[5];
	    state.last[6] = state.M[6];
	    state.last[7] = state.M[7];
            
            tpstUnloadBlock(&state, block);
        
            buffer[c] = block[0];
            buffer[c+1] = block[1];
            buffer[c+2] = block[2];
            buffer[c+3] = block[3];
            buffer[c+4] = block[4];
            buffer[c+5] = block[5];
            buffer[c+6] = block[6];
            buffer[c+7] = block[7];
            buffer[c+8] = block[8];
            buffer[c+9] = block[9];
            buffer[c+10] = block[10];
            buffer[c+11] = block[11];
            buffer[c+12] = block[12];
            buffer[c+13] = block[13];
            buffer[c+14] = block[14];
            buffer[c+15] = block[15];
            buffer[c+16] = block[16];
            buffer[c+17] = block[17];
            buffer[c+18] = block[18];
            buffer[c+19] = block[19];
            buffer[c+20] = block[20];
            buffer[c+21] = block[21];
            buffer[c+22] = block[22];
            buffer[c+23] = block[23];
            buffer[c+24] = block[24];
            buffer[c+25] = block[25];
            buffer[c+26] = block[26];
            buffer[c+27] = block[27];
            buffer[c+28] = block[28];
            buffer[c+29] = block[29];
            buffer[c+30] = block[30];
            buffer[c+31] = block[31];
            c += 32;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void tpstCBCDecrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    int pkctxt_len = 768;
    int Sctxt_len = 768;
    int Yctxt_len = 768;
    struct qloq_ctx ctx;
    BIGNUM *tmp;
    BIGNUM *tmpS;
    BIGNUM *BNctxt;
    tmp = BN_new();
    tmpS = BN_new();
    BNctxt = BN_new();
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &ctx);
    load_pkfile(keyfile2, &ctx);

    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *kwnonce[keywrap_ivlen];
    unsigned char *passtmp[pkctxt_len];
    unsigned char *Ytmp[Yctxt_len];
    unsigned char *signtmp[Sctxt_len];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen - pkctxt_len - Sctxt_len - Yctxt_len;
    int extrabytes = 32 - (datalen % 32);
    fseek(infile, 0, SEEK_SET);

    fread(&mac, 1, mac_length, infile);
    fread(passtmp, 1, pkctxt_len, infile);
    fread(Ytmp, 1, Yctxt_len, infile);
    fread(&signtmp, 1, Sctxt_len, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    BN_bin2bn(passtmp, pkctxt_len, tmp);
    decloak(&ctx, BNctxt, tmp);
    int ctxtbytes = BN_num_bytes(BNctxt);
    unsigned char password[ctxtbytes];
    BN_bn2bin(BNctxt, password);
    unsigned char *passkey[password_len];
    mypad_decrypt(passtmp, password, ctxtbytes, Ytmp);
    memcpy(passkey, passtmp, password_len);
    BN_bin2bn(signtmp, Sctxt_len, tmpS);
    if (verify(&ctx, tmp, BNctxt) != 0) {
        printf("Error: Signature verification failed. Message is not authentic.\n");
        exit(2);
    }

    manja_kdf(passkey, ctxtbytes, key, key_length, kdf_salt, salt_len, kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    struct tpstState state;
    int count = 0;
    uint8_t block[32] = {0};
    int blocksize = 32;
    int blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
        bufsize = extra;
    }
    int c = 0;
    int b;
    int i;
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length + pkctxt_len + Sctxt_len + Yctxt_len), SEEK_SET);
        tpstGenSubKeys(&state, keyprime, key_length);
        state.last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
        state.last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
        state.last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
        state.last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
        state.last[4] = ((iv[16] << 24) + (iv[17] << 16) + (iv[18] << 8) + iv[19]);
        state.last[5] = ((iv[20] << 24) + (iv[21] << 16) + (iv[22] << 8) + iv[23]);
        state.last[6] = ((iv[24] << 24) + (iv[25] << 16) + (iv[26] << 8) + iv[27]);
        state.last[7] = ((iv[28] << 24) + (iv[29] << 16) + (iv[30] << 8) + iv[31]);
        for (i = 0; i < blocks; i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / blocksize;
            int bextra = bufsize % blocksize;
            if (bextra != 0) {
                bblocks += 1;
            }
            for (b = 0; b < bblocks; b++) {
                block[0] = buffer[c];
                block[1] = buffer[c+1];
                block[2] = buffer[c+2];
                block[3] = buffer[c+3];
                block[4] = buffer[c+4];
                block[5] = buffer[c+5];
                block[6] = buffer[c+6];
                block[7] = buffer[c+7];
                block[8] = buffer[c+8];
                block[9] = buffer[c+9];
                block[10] = buffer[c+10];
                block[11] = buffer[c+11];
                block[12] = buffer[c+12];
                block[13] = buffer[c+13];
                block[14] = buffer[c+14];
                block[15] = buffer[c+15];
                block[16] = buffer[c+16];
                block[17] = buffer[c+17];
                block[18] = buffer[c+18];
                block[19] = buffer[c+19];
                block[20] = buffer[c+20];
                block[21] = buffer[c+21];
                block[22] = buffer[c+22];
                block[23] = buffer[c+23];
                block[24] = buffer[c+24];
                block[25] = buffer[c+25];
                block[26] = buffer[c+26];
                block[27] = buffer[c+27];
                block[28] = buffer[c+28];
                block[29] = buffer[c+29];
                block[30] = buffer[c+30];
                block[31] = buffer[c+31];
                tpstLoadBlock(&state, block);

	        state.next[0] = state.M[0];
	        state.next[1] = state.M[1];
	        state.next[2] = state.M[2];
	        state.next[3] = state.M[3];
	        state.next[4] = state.M[4];
	        state.next[5] = state.M[5];
	        state.next[6] = state.M[6];
	        state.next[7] = state.M[7];

                tpstBlockDecrypt(&state);
        
	        state.M[0] ^= state.last[0];
	        state.M[1] ^= state.last[1];
	        state.M[2] ^= state.last[2];
	        state.M[3] ^= state.last[3];
	        state.M[4] ^= state.last[4];
	        state.M[5] ^= state.last[5];
	        state.M[6] ^= state.last[6];
	        state.M[7] ^= state.last[7];

	        state.last[0] = state.next[0];
	        state.last[1] = state.next[1];
	        state.last[2] = state.next[2];
	        state.last[3] = state.next[3];
	        state.last[4] = state.next[4];
	        state.last[5] = state.next[5];
	        state.last[6] = state.next[6];
	        state.last[7] = state.next[7];

                tpstUnloadBlock(&state, block);

                buffer[c] = block[0];
                buffer[c+1] = block[1];
                buffer[c+2] = block[2];
                buffer[c+3] = block[3];
                buffer[c+4] = block[4];
                buffer[c+5] = block[5];
                buffer[c+6] = block[6];
                buffer[c+7] = block[7];
                buffer[c+8] = block[8];
                buffer[c+9] = block[9];
                buffer[c+10] = block[10];
                buffer[c+11] = block[11];
                buffer[c+12] = block[12];
                buffer[c+13] = block[13];
                buffer[c+14] = block[14];
                buffer[c+15] = block[15];
                buffer[c+16] = block[16];
                buffer[c+17] = block[17];
                buffer[c+18] = block[18];
                buffer[c+19] = block[19];
                buffer[c+20] = block[20];
                buffer[c+21] = block[21];
                buffer[c+22] = block[22];
                buffer[c+23] = block[23];
                buffer[c+24] = block[24];
                buffer[c+25] = block[25];
                buffer[c+26] = block[26];
                buffer[c+27] = block[27];
                buffer[c+28] = block[28];
                buffer[c+29] = block[29];
                buffer[c+30] = block[30];
                buffer[c+31] = block[31];
                c += 32;
            }

	    if (i == (blocks - 1)) {
	        int padcheck = buffer[bufsize - 1];
	        int g = bufsize - 1;
	        for (int p = 0; p < padcheck; p++) {
                    if ((int)buffer[g] == padcheck) {
                        count += 1;
		    }
		    g = g - 1;
                }
                if (padcheck == count) {
                    bufsize = bufsize - count;
                }
	    }
            fwrite(buffer, 1, bufsize, outfile);
        }
        fclose(infile);
        fclose(outfile);
    } 
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
