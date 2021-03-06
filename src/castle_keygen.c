#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <openssl/bn.h>
#include "common/common.c"
#include "ciphers/qloqRSA.c"
#include "ciphers/uvajda_oneshot.c"
#include "common/crypto_funcs.c"
#include "hmac/hx.c"
#include "kdf/hxkdf.c"
#include "ciphers/zanderfish3_cbc.c"
#include "keygen/keygen.c"

int main(int argc, char *argv[]) {
    int kdf_iterations = 100000;
    unsigned char *kdf_salt = "KryptoMagickDarkCastleVersion1.0";
    int psize = 3072;
    char *prefix = "castle";
    if (argc >= 2) {
        psize = atoi(argv[1]);
    }
    unsigned char * passphrase[64] = {0};
    capturePassphrase(passphrase);
    qloq_keygen_pkg(psize, prefix, passphrase, kdf_salt, kdf_iterations);
    return 0;
}
