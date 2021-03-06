#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* KryptoMagick Sp Di Cipher (Sep Di) */

uint8_t spdiS0[256] = {113, 206, 43, 136, 229, 66, 159, 252, 89, 182, 19, 112, 205, 42, 135, 228, 65, 158, 251, 88, 181, 18, 111, 204, 41, 134, 227, 64, 157, 250, 87, 180, 17, 110, 203, 40, 133, 226, 63, 156, 249, 86, 179, 16, 109, 202, 39, 132, 225, 62, 155, 248, 85, 178, 15, 108, 201, 38, 131, 224, 61, 154, 247, 84, 177, 14, 107, 200, 37, 130, 223, 60, 153, 246, 83, 176, 13, 106, 199, 36, 129, 222, 59, 152, 245, 82, 175, 12, 105, 198, 35, 128, 221, 58, 151, 244, 81, 174, 11, 104, 197, 34, 127, 220, 57, 150, 243, 80, 173, 10, 103, 196, 33, 126, 219, 56, 149, 242, 79, 172, 9, 102, 195, 32, 125, 218, 55, 148, 241, 78, 171, 8, 101, 194, 31, 124, 217, 54, 147, 240, 77, 170, 7, 100, 193, 30, 123, 216, 53, 146, 239, 76, 169, 6, 99, 192, 29, 122, 215, 52, 145, 238, 75, 168, 5, 98, 191, 28, 121, 214, 51, 144, 237, 74, 167, 4, 97, 190, 27, 120, 213, 50, 143, 236, 73, 166, 3, 96, 189, 26, 119, 212, 49, 142, 235, 72, 165, 2, 95, 188, 25, 118, 211, 48, 141, 234, 71, 164, 1, 94, 187, 24, 117, 210, 47, 140, 233, 70, 163, 0, 93, 186, 23, 116, 209, 46, 139, 232, 69, 162, 255, 92, 185, 22, 115, 208, 45, 138, 231, 68, 161, 254, 91, 184, 21, 114, 207, 44, 137, 230, 67, 160, 253, 90, 183, 20};
uint8_t spdiS0i[256] = {219, 208, 197, 186, 175, 164, 153, 142, 131, 120, 109, 98, 87, 76, 65, 54, 43, 32, 21, 10, 255, 244, 233, 222, 211, 200, 189, 178, 167, 156, 145, 134, 123, 112, 101, 90, 79, 68, 57, 46, 35, 24, 13, 2, 247, 236, 225, 214, 203, 192, 181, 170, 159, 148, 137, 126, 115, 104, 93, 82, 71, 60, 49, 38, 27, 16, 5, 250, 239, 228, 217, 206, 195, 184, 173, 162, 151, 140, 129, 118, 107, 96, 85, 74, 63, 52, 41, 30, 19, 8, 253, 242, 231, 220, 209, 198, 187, 176, 165, 154, 143, 132, 121, 110, 99, 88, 77, 66, 55, 44, 33, 22, 11, 0, 245, 234, 223, 212, 201, 190, 179, 168, 157, 146, 135, 124, 113, 102, 91, 80, 69, 58, 47, 36, 25, 14, 3, 248, 237, 226, 215, 204, 193, 182, 171, 160, 149, 138, 127, 116, 105, 94, 83, 72, 61, 50, 39, 28, 17, 6, 251, 240, 229, 218, 207, 196, 185, 174, 163, 152, 141, 130, 119, 108, 97, 86, 75, 64, 53, 42, 31, 20, 9, 254, 243, 232, 221, 210, 199, 188, 177, 166, 155, 144, 133, 122, 111, 100, 89, 78, 67, 56, 45, 34, 23, 12, 1, 246, 235, 224, 213, 202, 191, 180, 169, 158, 147, 136, 125, 114, 103, 92, 81, 70, 59, 48, 37, 26, 15, 4, 249, 238, 227, 216, 205, 194, 183, 172, 161, 150, 139, 128, 117, 106, 95, 84, 73, 62, 51, 40, 29, 18, 7, 252, 241, 230};
uint8_t spdiA0[256] = {27, 9, 33, 221, 151, 121, 13, 41, 157, 245, 17, 77, 171, 21, 231, 93, 51, 125, 163, 37, 91, 19, 207, 229, 31, 217, 139, 5, 131, 97, 181, 197, 135, 15, 243, 161, 59, 61, 117, 173, 81, 113, 63, 57, 193, 177, 129, 45, 101, 213, 239, 103, 71, 205, 127, 107, 83, 87, 183, 233, 227, 209, 219, 47, 105, 67, 141, 153, 247, 115, 237, 43, 109, 241, 199, 147, 25, 133, 75, 189, 179, 201, 3, 39, 7, 143, 255, 55, 49, 155, 225, 169, 149, 53, 185, 167, 251, 1, 195, 73, 253, 203, 249, 191, 159, 175, 11, 89, 95, 215, 235, 69, 223, 111, 165, 123, 119, 145, 211, 65, 35, 187, 29, 23, 79, 137, 99, 85, 179, 101, 67, 125, 75, 29, 65, 213, 241, 229, 249, 9, 123, 89, 247, 21, 27, 13, 193, 93, 161, 149, 223, 209, 131, 145, 235, 221, 57, 233, 153, 7, 255, 133, 173, 165, 175, 55, 3, 237, 25, 205, 135, 113, 119, 39, 151, 177, 203, 201, 207, 81, 23, 121, 37, 137, 35, 85, 107, 253, 197, 91, 191, 69, 239, 63, 79, 115, 215, 77, 245, 11, 41, 143, 111, 83, 141, 99, 181, 59, 163, 147, 231, 217, 139, 53, 251, 51, 1, 87, 219, 17, 189, 97, 243, 15, 185, 61, 33, 105, 159, 49, 195, 129, 155, 109, 47, 211, 71, 103, 95, 183, 227, 171, 31, 19, 199, 45, 157, 187, 5, 167, 127, 225, 43, 73, 169, 117};
uint8_t spdiA0i[256] = {19, 57, 225, 117, 39, 201, 197, 25, 181, 93, 241, 133, 3, 61, 215, 245, 251, 213, 11, 173, 211, 27, 47, 237, 223, 105, 35, 205, 43, 161, 157, 13, 55, 239, 59, 97, 243, 21, 221, 37, 177, 145, 191, 9, 65, 81, 129, 165, 109, 125, 15, 87, 119, 5, 127, 67, 219, 103, 7, 89, 203, 49, 83, 207, 217, 107, 69, 169, 199, 187, 229, 131, 101, 17, 247, 155, 41, 77, 99, 149, 123, 121, 171, 151, 183, 111, 255, 135, 209, 147, 33, 153, 189, 29, 137, 23, 51, 1, 235, 249, 85, 227, 73, 63, 95, 79, 163, 233, 159, 231, 195, 141, 31, 143, 45, 179, 71, 113, 91, 193, 139, 115, 53, 167, 175, 185, 75, 253, 123, 109, 107, 213, 99, 53, 193, 125, 17, 237, 73, 57, 179, 233, 199, 61, 19, 197, 65, 245, 97, 189, 31, 49, 43, 113, 195, 117, 9, 89, 169, 183, 255, 77, 37, 45, 79, 135, 171, 229, 41, 5, 55, 145, 71, 151, 39, 81, 227, 121, 47, 177, 167, 201, 173, 185, 139, 253, 67, 85, 13, 211, 63, 141, 15, 191, 175, 187, 231, 133, 93, 163, 25, 111, 143, 219, 69, 75, 157, 243, 11, 155, 215, 105, 35, 29, 51, 251, 1, 103, 83, 241, 149, 161, 59, 239, 137, 21, 225, 217, 95, 209, 235, 129, 147, 101, 207, 91, 119, 87, 159, 7, 203, 3, 223, 27, 247, 165, 181, 115, 205, 23, 127, 33, 131, 249, 153, 221};

struct spdiState {
    uint32_t K[14][4];
    uint32_t M[4];
    uint32_t last[4];
    uint32_t next[4];
    int rounds;
};

struct spdiKSAState {
    uint32_t r[8];
};

void spdiKSF(struct spdiState *state, struct spdiKSAState *KSstate) {
    int r, i;
    uint32_t tmp1[8] = {0};
    state->K[0][0] = KSstate->r[0];
    state->K[0][1] = KSstate->r[1];
    state->K[0][2] = KSstate->r[2];
    state->K[0][3] = KSstate->r[3];
    state->K[state->rounds - 1][0] = KSstate->r[4];
    state->K[state->rounds - 1][1] = KSstate->r[5];
    state->K[state->rounds - 1][2] = KSstate->r[6];
    state->K[state->rounds - 1][3] = KSstate->r[7];
    for (r = 1; r < state->rounds - 1; r++) {
        for (i = 0; i < 8; i++) {
            KSstate->r[i] += (rotl32(KSstate->r[(i + 1) & 0x07], 21) + state->K[(r - 1) % state->rounds][i & 0x03]);
            state->K[r][i & 0x03] += (KSstate->r[i] + tmp1[i] ^ (rotr32(tmp1[i], 10) ^ rotl32(KSstate->r[i], 21)));
            tmp1[i] += state->K[r][i & 0x03];
        }
    }
}

void spdiGenSubKeys(struct spdiState * state, unsigned char * key, int keylen) {
    struct spdiKSAState kstate;
    int c = 0;
    int i;
    int s;
    state->rounds = 14;
    memset(state->K, 0, state->rounds*(4*sizeof(uint32_t)));
    memset(kstate.r, 0, 8*sizeof(uint32_t));
    memset(state->last, 0, 4*sizeof(uint32_t));
    memset(state->next, 0, 4*sizeof(uint32_t));

    for (i = 0; i < (keylen / 4); i++) {
        kstate.r[i] = (((uint32_t)key[c] << 24) + ((uint32_t)key[c+1] << 16) + ((uint32_t)key[c+2] << 8) + (uint32_t)key[c+3]);
        c += 4;
    }
    spdiKSF(state, &kstate);
}

void spdiLoadBlock(struct spdiState *state, uint8_t *block) {
    state->M[0] = ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->M[1] = ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->M[2] = ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->M[3] = ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
}

void spdiUnloadBlock(struct spdiState *state, uint8_t *block) {
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
}

void spdiSubBlock(struct spdiState *state) {
    state->M[0] = ((spdiS0[(state->M[0] & 0xFF000000) >> 24] << 24) + (spdiS0[(state->M[0] & 0x00FF0000) >> 16] << 16) + (spdiS0[(state->M[0] & 0x0000FF00) >> 8] << 8) + spdiS0[(state->M[0] & 0x000000FF)]);
    state->M[1] = ((spdiS0[(state->M[1] & 0xFF000000) >> 24] << 24) + (spdiS0[(state->M[1] & 0x00FF0000) >> 16] << 16) + (spdiS0[(state->M[1] & 0x0000FF00) >> 8] << 8) + spdiS0[(state->M[1] & 0x000000FF)]);
    state->M[2] = ((spdiS0[(state->M[2] & 0xFF000000) >> 24] << 24) + (spdiS0[(state->M[2] & 0x00FF0000) >> 16] << 16) + (spdiS0[(state->M[2] & 0x0000FF00) >> 8] << 8) + spdiS0[(state->M[2] & 0x000000FF)]);
    state->M[3] = ((spdiS0[(state->M[3] & 0xFF000000) >> 24] << 24) + (spdiS0[(state->M[3] & 0x00FF0000) >> 16] << 16) + (spdiS0[(state->M[3] & 0x0000FF00) >> 8] << 8) + spdiS0[(state->M[3] & 0x000000FF)]);
}

void spdiInvSubBlock(struct spdiState *state) {
    state->M[0] = ((spdiS0i[(state->M[0] & 0xFF000000) >> 24] << 24) + (spdiS0i[(state->M[0] & 0x00FF0000) >> 16] << 16) + (spdiS0i[(state->M[0] & 0x0000FF00) >> 8] << 8) + spdiS0i[(state->M[0] & 0x000000FF)]);
    state->M[1] = ((spdiS0i[(state->M[1] & 0xFF000000) >> 24] << 24) + (spdiS0i[(state->M[1] & 0x00FF0000) >> 16] << 16) + (spdiS0i[(state->M[1] & 0x0000FF00) >> 8] << 8) + spdiS0i[(state->M[1] & 0x000000FF)]);
    state->M[2] = ((spdiS0i[(state->M[2] & 0xFF000000) >> 24] << 24) + (spdiS0i[(state->M[2] & 0x00FF0000) >> 16] << 16) + (spdiS0i[(state->M[2] & 0x0000FF00) >> 8] << 8) + spdiS0i[(state->M[2] & 0x000000FF)]);
    state->M[3] = ((spdiS0i[(state->M[3] & 0xFF000000) >> 24] << 24) + (spdiS0i[(state->M[3] & 0x00FF0000) >> 16] << 16) + (spdiS0i[(state->M[3] & 0x0000FF00) >> 8] << 8) + spdiS0i[(state->M[3] & 0x000000FF)]);
}

void spdiRotateLeft(struct spdiState *state) {
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
}

void spdiRotateRight(struct spdiState *state) {
    uint32_t tmp;
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

void spdiMixBlock(struct spdiState *state) {
    state->M[0] = (((((state->M[0] & 0xFF000000) >> 24) * spdiA0[(state->M[1] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[0] & 0x00FF0000) >> 16) * spdiA0[(state->M[1] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[0] & 0x0000FF00) >> 8) * spdiA0[(state->M[1] & 0x00000FF0) >> 8]) & 0xFF) << 8) + (((((state->M[0] & 0x000000FF)) * spdiA0[(state->M[1] & 0x000000FF)]) & 0xFF));
    state->M[1] = (((((state->M[1] & 0xFF000000) >> 24) * spdiA0[(state->M[2] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[1] & 0x00FF0000) >> 16) * spdiA0[(state->M[2] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[1] & 0x0000FF00) >> 8) * spdiA0[(state->M[2] & 0x00000FF0) >> 8]) & 0xFF) << 8) + (((((state->M[1] & 0x000000FF)) * spdiA0[(state->M[2] & 0x000000FF)]) & 0xFF));
    state->M[2] = (((((state->M[2] & 0xFF000000) >> 24) * spdiA0[(state->M[3] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[2] & 0x00FF0000) >> 16) * spdiA0[(state->M[3] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[2] & 0x0000FF00) >> 8) * spdiA0[(state->M[3] & 0x00000FF0) >> 8]) & 0xFF) << 8) + (((((state->M[2] & 0x000000FF)) * spdiA0[(state->M[3] & 0x000000FF)]) & 0xFF));
    state->M[3] = (((((state->M[3] & 0xFF000000) >> 24) * spdiA0[(state->M[0] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[3] & 0x00FF0000) >> 16) * spdiA0[(state->M[0] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[3] & 0x0000FF00) >> 8) * spdiA0[(state->M[0] & 0x0000FF00) >> 8]) & 0xFF) << 8) + (((((state->M[3] & 0x000000FF)) * spdiA0[(state->M[0] & 0x000000FF)]) & 0xFF));

    state->M[0] += state->M[1];
    state->M[2] += state->M[0];
    state->M[1] += state->M[3];
    state->M[3] += state->M[2];

    state->M[1] = rotl32(state->M[1], 21);
    state->M[3] = rotl32(state->M[3], 6);

    state->M[0] += state->M[2];
    state->M[1] += state->M[3];
    state->M[2] += state->M[0];
    state->M[3] += state->M[1];
}

void spdiInvMixBlock(struct spdiState *state) {
    state->M[3] -= state->M[1];
    state->M[2] -= state->M[0];
    state->M[1] -= state->M[3];
    state->M[0] -= state->M[2];
    
    state->M[3] = rotr32(state->M[3], 6);
    state->M[1] = rotr32(state->M[1], 21);

    state->M[3] -= state->M[2];
    state->M[1] -= state->M[3];
    state->M[2] -= state->M[0];
    state->M[0] -= state->M[1];

    state->M[3] = (((((state->M[3] & 0xFF000000) >> 24) * spdiA0i[(state->M[0] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[3] & 0x00FF0000) >> 16) * spdiA0i[(state->M[0] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[3] & 0x0000FF00) >> 8) * spdiA0i[(state->M[0] & 0x0000FF00) >> 8]) & 0xFF) << 8) + (((((state->M[3] & 0x000000FF)) * spdiA0i[(state->M[0] & 0x000000FF)]) & 0xFF));
    state->M[2] = (((((state->M[2] & 0xFF000000) >> 24) * spdiA0i[(state->M[3] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[2] & 0x00FF0000) >> 16) * spdiA0i[(state->M[3] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[2] & 0x0000FF00) >> 8) * spdiA0i[(state->M[3] & 0x00000FF0) >> 8]) & 0xFF) << 8) + (((((state->M[2] & 0x000000FF)) * spdiA0i[(state->M[3] & 0x000000FF)]) & 0xFF));
    state->M[1] = (((((state->M[1] & 0xFF000000) >> 24) * spdiA0i[(state->M[2] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[1] & 0x00FF0000) >> 16) * spdiA0i[(state->M[2] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[1] & 0x0000FF00) >> 8) * spdiA0i[(state->M[2] & 0x00000FF0) >> 8]) & 0xFF) << 8) + (((((state->M[1] & 0x000000FF)) * spdiA0i[(state->M[2] & 0x000000FF)]) & 0xFF));
    state->M[0] = (((((state->M[0] & 0xFF000000) >> 24) * spdiA0i[(state->M[1] & 0xFF000000) >> 24]) & 0xFF) << 24) + (((((state->M[0] & 0x00FF0000) >> 16) * spdiA0i[(state->M[1] & 0x00FF0000) >> 16]) & 0xFF) << 16) + (((((state->M[0] & 0x0000FF00) >> 8) * spdiA0i[(state->M[1] & 0x00000FF0) >> 8]) & 0xFF) << 8) + (((((state->M[0] & 0x000000FF)) * spdiA0i[(state->M[1] & 0x000000FF)]) & 0xFF));
}

void spdiAddRoundKey(struct spdiState *state, int round) {
    state->M[0] ^= state->K[round][0];
    state->M[1] ^= state->K[round][1];
    state->M[2] ^= state->K[round][2];
    state->M[3] ^= state->K[round][3];
}

void spdiBlockEncrypt(struct spdiState * state) {
    for (int r = 0; r < state->rounds; r++) {
        spdiSubBlock(state);
        spdiRotateLeft(state);
        spdiMixBlock(state);
        spdiAddRoundKey(state, r);
    }
}

void spdiBlockDecrypt(struct spdiState * state) {
    for (int r = (state->rounds - 1); r != -1; r--) {
        spdiAddRoundKey(state, r);
        spdiInvMixBlock(state);
        spdiRotateRight(state);
        spdiInvSubBlock(state);
    }
}

void spdiCBCEncrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    zander3_cbc_decrypt_kf(keyfile2, 32, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &Sctx);
    load_pkfile(keyfile1, &ctx);
    unsigned char *password[password_len];
    getRandomBytes(password, password_len);
    BIGNUM *tmp;
    BIGNUM *BNctxt;
    BIGNUM *S;
    tmp = BN_new();
    BNctxt = BN_new();
    S = BN_new();
    unsigned char *X[mask_bytes];
    unsigned char *Y[mask_bytes];
    getRandomBytes(Y, mask_bytes);
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
    getRandomBytes(&iv, nonce_length);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    hxKDF(password, password_len, key, key_length, kdf_salt, salt_len, kdf_iterations);
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

    struct spdiState state;
    uint8_t block[16] = {0};
    int blocksize = 16;
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
    spdiGenSubKeys(&state, keyprime, key_length);
    state.last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
    state.last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
    state.last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
    state.last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
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
            spdiLoadBlock(&state, block);
	 
	    state.M[0] ^= state.last[0];
	    state.M[1] ^= state.last[1];
	    state.M[2] ^= state.last[2];
	    state.M[3] ^= state.last[3];

            spdiBlockEncrypt(&state);

	    state.last[0] = state.M[0];
	    state.last[1] = state.M[1];
	    state.last[2] = state.M[2];
	    state.last[3] = state.M[3];
            
            spdiUnloadBlock(&state, block);
        
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
            c += 16;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    hxKDF(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    hxHMACFILE(outputfile, mac_key, key_length);
}

void spdiCBCDecrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
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
    zander3_cbc_decrypt_kf(keyfile1, 32, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &ctx);
    load_pkfile(keyfile2, &ctx);

    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
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
    int extrabytes = 16 - (datalen % 16);
    fseek(infile, 0, SEEK_SET);

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

    hxKDF(passkey, ctxtbytes, key, key_length, kdf_salt, salt_len, kdf_iterations);
    hxKDF(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    struct spdiState state;
    int count = 0;
    uint8_t block[16] = {0};
    int blocksize = 16;
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
    if (hxHMACVerifyFILE(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (keywrap_ivlen + nonce_length + key_length + pkctxt_len + Sctxt_len + Yctxt_len), SEEK_SET);
        spdiGenSubKeys(&state, keyprime, key_length);
        state.last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
        state.last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
        state.last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
        state.last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
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
                spdiLoadBlock(&state, block);

	        state.next[0] = state.M[0];
	        state.next[1] = state.M[1];
	        state.next[2] = state.M[2];
	        state.next[3] = state.M[3];

                spdiBlockDecrypt(&state);
        
	        state.M[0] ^= state.last[0];
	        state.M[1] ^= state.last[1];
	        state.M[2] ^= state.last[2];
	        state.M[3] ^= state.last[3];

	        state.last[0] = state.next[0];
	        state.last[1] = state.next[1];
	        state.last[2] = state.next[2];
	        state.last[3] = state.next[3];

                spdiUnloadBlock(&state, block);

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
                c += 16;
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
