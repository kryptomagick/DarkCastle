uint32_t hxC0[8] = {0xe2522dcb, 0xc6685b1d, 0xc318af38, 0x923481c0, 0xefda0713, 0x9aa44f2e, 0xf64a2a14, 0xec05e8fb};

struct hxState {
    uint32_t M[4][4];
    uint32_t P[4][4];
    uint8_t H512[64];
    uint8_t H256[32];
    int rounds;
};

void hxAbsorb(struct hxState *state, uint8_t *block) {
    state->M[0][0] ^= (block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3];
    state->M[0][1] ^= (block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7];
    state->M[0][2] ^= (block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11];
    state->M[0][3] ^= (block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15];
    state->M[1][0] ^= (block[16] << 24) + (block[17] << 16) + (block[18] << 8) + block[19];
    state->M[1][1] ^= (block[20] << 24) + (block[21] << 16) + (block[22] << 8) + block[23];
    state->M[1][2] ^= (block[24] << 24) + (block[25] << 16) + (block[26] << 8) + block[27];
    state->M[1][3] ^= (block[28] << 24) + (block[29] << 16) + (block[30] << 8) + block[31];
    state->M[2][0] ^= (block[32] << 24) + (block[33] << 16) + (block[34] << 8) + block[35];
    state->M[2][1] ^= (block[36] << 24) + (block[37] << 16) + (block[38] << 8) + block[39];
    state->M[2][2] ^= (block[40] << 24) + (block[41] << 16) + (block[42] << 8) + block[43];
    state->M[2][3] ^= (block[44] << 24) + (block[45] << 16) + (block[46] << 8) + block[47];
    state->M[3][0] ^= (block[48] << 24) + (block[49] << 16) + (block[50] << 8) + block[51];
    state->M[3][1] ^= (block[52] << 24) + (block[53] << 16) + (block[54] << 8) + block[55];
    state->M[3][2] ^= (block[56] << 24) + (block[57] << 16) + (block[58] << 8) + block[59];
    state->M[3][3] ^= (block[60] << 24) + (block[61] << 16) + (block[62] << 8) + block[63];
}

void hxMixA(struct hxState *state) {
    state->M[0][0] += state->M[1][0];
    state->M[0][1] += state->M[1][1];
    state->M[0][2] += state->M[1][2];
    state->M[0][3] += state->M[1][3];
    state->M[1][0] += state->M[2][0];
    state->M[1][1] += state->M[2][1];
    state->M[1][2] += state->M[2][2];
    state->M[1][3] += state->M[2][3];
    state->M[2][0] += state->M[3][0];
    state->M[2][1] += state->M[3][1];
    state->M[2][2] += state->M[3][2];
    state->M[2][3] += state->M[3][3];
    state->M[3][0] += state->M[0][0];
    state->M[3][1] += state->M[0][1];
    state->M[3][2] += state->M[0][2];
    state->M[3][3] += state->M[0][3];
}

void hxRotate(struct hxState *state) {
    uint32_t tmp[4];
    memcpy(tmp, state->M[0], 4*(sizeof(uint32_t)));
    memcpy(state->M[0], state->M[1], 4*(sizeof(uint32_t)));
    memcpy(state->M[1], tmp, 4*(sizeof(uint32_t)));

    memcpy(tmp, state->M[1], 4*(sizeof(uint32_t)));
    memcpy(state->M[1], state->M[2], 4*(sizeof(uint32_t)));
    memcpy(state->M[2], tmp, 4*(sizeof(uint32_t)));

    memcpy(tmp, state->M[2], 4*(sizeof(uint32_t)));
    memcpy(state->M[2], state->M[3], 4*(sizeof(uint32_t)));
    memcpy(state->M[3], tmp, 4*(sizeof(uint32_t)));
}

void hxMixB(struct hxState *state) {
    state->M[0][0] += state->M[3][2];
    state->M[0][1] += state->M[3][0];
    state->M[0][2] += state->M[1][2];
    state->M[0][3] += state->M[2][3];
    state->M[1][0] += state->M[0][1];
    state->M[1][1] += state->M[3][1];
    state->M[1][2] += state->M[2][1];
    state->M[1][3] += state->M[0][0];
    state->M[2][0] += state->M[0][2];
    state->M[2][1] += state->M[1][3];
    state->M[2][2] += state->M[3][3];
    state->M[2][3] += state->M[1][1];
    state->M[3][0] += state->M[0][3];
    state->M[3][1] += state->M[1][0];
    state->M[3][2] += state->M[2][2];
    state->M[3][3] += state->M[2][0];
    state->M[0][0] = rotl32(state->M[0][0], 6);
    state->M[0][1] = rotl32(state->M[0][1], 21);
    state->M[0][2] = rotl32(state->M[0][2], 10);
    state->M[0][3] = rotl32(state->M[0][3], 3);
}

void hxMixP(struct hxState *state) {
    state->M[0][0] += state->P[0][0];
    state->M[0][1] += state->P[0][1];
    state->M[0][2] += state->P[0][2];
    state->M[0][3] += state->P[0][3];
    state->M[1][0] += state->P[1][0];
    state->M[1][1] += state->P[1][1];
    state->M[1][2] += state->P[1][2];
    state->M[1][3] += state->P[1][3];
    state->M[2][0] += state->P[2][0];
    state->M[2][1] += state->P[2][1];
    state->M[2][2] += state->P[2][2];
    state->M[2][3] += state->P[2][3];
    state->M[3][0] += state->P[3][0];
    state->M[3][1] += state->P[3][1];
    state->M[3][2] += state->P[3][2];
    state->M[3][3] += state->P[3][3];
}

void hxUpdate(struct hxState *state, uint8_t *block) {
    hxAbsorb(state, block);
    for (int r = 0; r < state->rounds; r++) {
        memcpy(state->P, state->M, 16*(sizeof(uint32_t)));
        hxMixA(state);
        hxRotate(state);
        hxMixB(state);
        hxMixP(state);
    }
}

void hxOutput(struct hxState *state) {
    state->H512[0] = (state->M[0][0] & 0xFF000000) >> 24;
    state->H512[1] = (state->M[0][0] & 0x00FF0000) >> 16;
    state->H512[2] = (state->M[0][0] & 0x0000FF00) >> 8;
    state->H512[3] = (state->M[0][0] & 0x000000FF);
    state->H512[4] = (state->M[0][1] & 0xFF000000) >> 24;
    state->H512[5] = (state->M[0][1] & 0x00FF0000) >> 16;
    state->H512[6] = (state->M[0][1] & 0x0000FF00) >> 8;
    state->H512[7] = (state->M[0][1] & 0x000000FF);
    state->H512[8] = (state->M[0][2] & 0xFF000000) >> 24;
    state->H512[9] = (state->M[0][2] & 0x00FF0000) >> 16;
    state->H512[10] = (state->M[0][2] & 0x0000FF00) >> 8;
    state->H512[11] = (state->M[0][2] & 0x000000FF);
    state->H512[12] = (state->M[0][3] & 0xFF000000) >> 24;
    state->H512[13] = (state->M[0][3] & 0x00FF0000) >> 16;
    state->H512[14] = (state->M[0][3] & 0x0000FF00) >> 8;
    state->H512[15] = (state->M[0][3] & 0x000000FF);
    state->H512[16] = (state->M[1][0] & 0xFF000000) >> 24;
    state->H512[17] = (state->M[1][0] & 0x00FF0000) >> 16;
    state->H512[18] = (state->M[1][0] & 0x0000FF00) >> 8;
    state->H512[19] = (state->M[1][0] & 0x000000FF);
    state->H512[20] = (state->M[1][1] & 0xFF000000) >> 24;
    state->H512[21] = (state->M[1][1] & 0x00FF0000) >> 16;
    state->H512[22] = (state->M[1][1] & 0x0000FF00) >> 8;
    state->H512[23] = (state->M[1][1] & 0x000000FF);
    state->H512[24] = (state->M[1][2] & 0xFF000000) >> 24;
    state->H512[25] = (state->M[1][2] & 0x00FF0000) >> 16;
    state->H512[26] = (state->M[1][2] & 0x0000FF00) >> 8;
    state->H512[27] = (state->M[1][2] & 0x000000FF);
    state->H512[28] = (state->M[1][3] & 0xFF000000) >> 24;
    state->H512[29] = (state->M[1][3] & 0x00FF0000) >> 16;
    state->H512[30] = (state->M[1][3] & 0x0000FF00) >> 8;
    state->H512[31] = (state->M[1][3] & 0x000000FF);
    state->H512[32] = (state->M[2][0] & 0xFF000000) >> 24;
    state->H512[33] = (state->M[2][0] & 0x00FF0000) >> 16;
    state->H512[34] = (state->M[2][0] & 0x0000FF00) >> 8;
    state->H512[35] = (state->M[2][0] & 0x000000FF);
    state->H512[36] = (state->M[2][1] & 0xFF000000) >> 24;
    state->H512[37] = (state->M[2][1] & 0x00FF0000) >> 16;
    state->H512[38] = (state->M[2][1] & 0x0000FF00) >> 8;
    state->H512[39] = (state->M[2][1] & 0x000000FF);
    state->H512[40] = (state->M[2][2] & 0xFF000000) >> 24;
    state->H512[41] = (state->M[2][2] & 0x00FF0000) >> 16;
    state->H512[42] = (state->M[2][2] & 0x0000FF00) >> 8;
    state->H512[43] = (state->M[2][2] & 0x000000FF);
    state->H512[44] = (state->M[2][3] & 0xFF000000) >> 24;
    state->H512[45] = (state->M[2][3] & 0x00FF0000) >> 16;
    state->H512[46] = (state->M[2][3] & 0x0000FF00) >> 8;
    state->H512[47] = (state->M[2][3] & 0x000000FF);
    state->H512[48] = (state->M[3][0] & 0xFF000000) >> 24;
    state->H512[49] = (state->M[3][0] & 0x00FF0000) >> 16;
    state->H512[50] = (state->M[3][0] & 0x0000FF00) >> 8;
    state->H512[51] = (state->M[3][0] & 0x000000FF);
    state->H512[52] = (state->M[3][1] & 0xFF000000) >> 24;
    state->H512[53] = (state->M[3][1] & 0x00FF0000) >> 16;
    state->H512[54] = (state->M[3][1] & 0x0000FF00) >> 8;
    state->H512[55] = (state->M[3][1] & 0x000000FF);
    state->H512[56] = (state->M[3][2] & 0xFF000000) >> 24;
    state->H512[57] = (state->M[3][2] & 0x00FF0000) >> 16;
    state->H512[58] = (state->M[3][2] & 0x0000FF00) >> 8;
    state->H512[59] = (state->M[3][2] & 0x000000FF);
    state->H512[60] = (state->M[3][3] & 0xFF000000) >> 24;
    state->H512[61] = (state->M[3][3] & 0x00FF0000) >> 16;
    state->H512[62] = (state->M[3][3] & 0x0000FF00) >> 8;
    state->H512[63] = (state->M[3][3] & 0x000000FF);
    memcpy(state->H256, state->H512, 32*(sizeof(uint8_t)));
}

void hxInit(struct hxState *state) {
    state->rounds = 32;
    memset(state->M, 0, 16*(sizeof(uint32_t)));
    state->M[2][0] = hxC0[0];
    state->M[2][1] = hxC0[1];
    state->M[2][2] = hxC0[2];
    state->M[2][3] = hxC0[3];
    state->M[3][0] = hxC0[4];
    state->M[3][1] = hxC0[5];
    state->M[3][2] = hxC0[6];
    state->M[3][3] = hxC0[7];
}

void hxKeyApply256(struct hxState *state, uint8_t *key) {
    state->M[0][0] ^= (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    state->M[0][1] ^= (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    state->M[0][2] ^= (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    state->M[0][3] ^= (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    state->M[1][0] ^= (key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19];
    state->M[1][1] ^= (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    state->M[1][2] ^= (key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27];
    state->M[1][3] ^= (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];
}
    
void hxHMACFILE(char *inputfile, unsigned char * key, int keylen) {
    struct hxState state;
    hxInit(&state);
    hxKeyApply256(&state, key);
    int blocksize = 64;
    FILE *infile;
    int i, datalen;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    int blocks = datalen / blocksize;
    int blocks_extra = datalen % blocksize;
    if ((blocks_extra != 0) || (datalen < blocksize)) {
        blocks += 1;
    }
    for (i = 0; i < blocks; i++) {
       if ((i == (blocks - 1)) && (blocks_extra != 0)) {
           blocksize = blocks_extra;
       }
       uint8_t block[64] = {0};
       fread(block, 1, blocksize, infile);
       hxUpdate(&state, block);
   }
   hxOutput(&state);
   fclose(infile);
   infile = fopen(inputfile, "ab");
   fwrite(state.H256, 1, 32, infile);
   fclose(infile);
}

int hxHMACVerifyFILE(char *inputfile, unsigned char * key, int keylen) {
    struct hxState state;
    hxInit(&state);
    hxKeyApply256(&state, key);
    int blocksize = 64;
    unsigned char mac[32] = {0};
    FILE *infile;
    int i;
    int datalen;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = ftell(infile);
    datalen -= 32;
    fseek(infile, 0, SEEK_SET);
    int blocks = datalen / blocksize;
    int blocks_extra = datalen % blocksize;
    if ((blocks_extra != 0) || (datalen < blocksize)) {
        blocks += 1;
    }
    for (i = 0; i < blocks; i++) {
       if ((i == (blocks - 1)) && (blocks_extra != 0)) {
           blocksize = blocks_extra;
       }
       uint8_t block[64] = {0};
       fread(block, 1, blocksize, infile);
       hxUpdate(&state, block);
   }
   hxOutput(&state);
   fread(mac, 1, 32, infile);
   fclose(infile);
   uint8_t tmp0 = 0;
   uint8_t tmp1 = 0;
   for (i = 0; i < 32; i++) {
        tmp0 ^= state.H256[i];
        tmp1 ^= mac[i];
   }
   if (tmp0 == tmp1) {
       return 0;
   }
   else {
       return 1;
   }
}
