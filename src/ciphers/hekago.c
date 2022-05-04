struct hekagoState {
    uint32_t r[8];
    int keylen;
};

void hekagoStreamUpdate0(struct hekagoState *state) {
    r[6] += 1;
    r[2] ^= r[1];
    r[4] += r[2];
    r[0] ^= r[3];
    r[1] += r[4];
    r[3] ^= r[5];
    r[5] += r[6];
    r[7] += 1;
    r[0] = rotl32(r[0], 21);
    r[1] = rotl32(r[1], 6);
    r[3] = rotl32(r[3], 45);
    r[4] = rotl32(r[4], 15);
}

void hekagoKeySetup(struct hekagoState *state, unsigned char *key, unsigned char *nonce) {
    r[2] = (nonce[0] << 56) + (nonce[1] << 48) + (nonce[2] << 40) + (nonce[3] << 32) + (nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7];
    r[5] = (nonce[8] << 56) + (nonce[9] << 48) + (nonce[10] << 40) + (nonce[11] << 32) + (nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15];
    r[0] = (key[0] << 56) + (key[1] << 48) + (key[2] << 40) + (key[3] << 32) + (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    r[1] = (key[8] << 56) + (key[9] << 48) + (key[10] << 40) + (key[11] << 32) + (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    r[3] = (key[16] << 56) + (key[17] << 48) + (key[18] << 40) + (key[19] << 32) + (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    r[4] = (key[24] << 56) + (key[25] << 48) + (key[26] << 40) + (key[27] << 32) + (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];
    r[6] = 0;
    r[7] = 1;
}
void hekago_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    load_pkfile(keyfile1, &ctx);
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &Sctx);
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
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
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
    uint32_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(password_ctxt, 1, mask_bytes, outfile);
    fwrite(Y, 1, mask_bytes, outfile);
    fwrite(sign_ctxt, 1, Sbytes, outfile);
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    struct hekagoState state;
    long c = 0;
    uint32_t i = 0;
    int l = 8;
    uint32_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint32_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    /*
    if (datalen < bufsize) {
        blocks = 1;
        bufsize = extra;
    } */
    uvajda_keysetup(&state, keyprime, nonce);
    for (uint32_t b = 0; b < blocks; b++) {
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        for (i = 0; i < (bufsize / 8); i++) {
            uvajda_F(&state);
            output = (((((((state.r[0] + state.r[6]) ^ state.r[1]) + state.r[5]) ^ state.r[2]) + state.r[4]) ^ state.r[3]) + state.r[7]);
            k[c] = (output & 0x00000000000000FF);
            k[c+1] = (output & 0x000000000000FF00) >> 8;
            k[c+2] = (output & 0x0000000000FF0000) >> 16;
            k[c+3] = (output & 0x00000000FF000000) >> 24;
            k[c+4] = (output & 0x000000FF00000000) >> 32;
            k[c+5] = (output & 0x0000FF0000000000) >> 40;
            k[c+6] = (output & 0x00FF000000000000) >> 48;
            k[c+7] = (output & 0xFF00000000000000) >> 56;
            c += 8;
        }
        for (i = 0 ; i < bufsize; i++) {
            buffer[i] = buffer[i] ^ k[i];
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void hekago_decrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
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
    unsigned char nonce[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    unsigned char *passtmp[mask_bytes];
    unsigned char *Ytmp[mask_bytes];
    unsigned char *signtmp[mask_bytes];
    unsigned char *kwnonce[keywrap_ivlen];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen - mask_bytes - mask_bytes - mask_bytes;
    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(passtmp, 1, mask_bytes, infile);
    fread(Ytmp, 1, mask_bytes, infile);
    fread(signtmp, 1, mask_bytes, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(nonce, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    BN_bin2bn(passtmp, mask_bytes, tmp);
    decloak(&ctx, BNctxt, tmp);
    int ctxtbytes = BN_num_bytes(BNctxt);
    unsigned char password[ctxtbytes];
    BN_bn2bin(BNctxt, password);
    unsigned char *passkey[password_len];
    mypad_decrypt(passtmp, password, ctxtbytes, Ytmp);
    memcpy(passkey, passtmp, password_len);
    BN_bin2bn(signtmp, mask_bytes, tmpS);
    if (verify(&ctx, tmp, BNctxt) != 0) {
        printf("Error: Signature verification failed. Message is not authentic.\n");
        exit(2);
    }

    manja_kdf(passkey, password_len, key, key_length, kdf_salt, salt_len, kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);

    key_wrap_decrypt(keyprime, key_length, key, kwnonce);
    struct hekagoState state;
    long c = 0;
    int i = 0;
    int l = 8;
    uint32_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint32_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length + (mask_bytes*3)), SEEK_SET);
        uvajda_keysetup(&state, keyprime, nonce);
        for (uint32_t b = 0; b < blocks; b++) {
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            if ((b == (blocks - 1)) && (extra != 0)) {
                bufsize = extra;
            }
            for (i = 0; i < (bufsize / 8); i++) {
                uvajda_F(&state);
                output = (((((((state.r[0] + state.r[6]) ^ state.r[1]) + state.r[5]) ^ state.r[2]) + state.r[4]) ^ state.r[3]) + state.r[7]);
                k[c] = (output & 0x00000000000000FF);
                k[c+1] = (output & 0x000000000000FF00) >> 8;
                k[c+2] = (output & 0x0000000000FF0000) >> 16;
                k[c+3] = (output & 0x00000000FF000000) >> 24;
                k[c+4] = (output & 0x000000FF00000000) >> 32;
                k[c+5] = (output & 0x0000FF0000000000) >> 40;
                k[c+6] = (output & 0x00FF000000000000) >> 48;
                k[c+7] = (output & 0xFF00000000000000) >> 56;
                c += 8;
            }
            for (i = 0 ; i < bufsize; i++) {
                buffer[i] = buffer[i] ^ k[i];
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
