#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "common/common.c"
#include "ciphers/qloqRSA.c"
#include "ciphers/uvajda_oneshot.c"
#include "common/crypto_funcs.c"
#include "hmac/hx.c"
#include "kdf/hxkdf.c"
#include "ciphers/zanderfish3_cbc.c"
#include "ciphers/uvajda.c"
#include "ciphers/darkcipher.c"
#include "ciphers/zanderfish3_ofb.c"
#include "ciphers/spock_cbc.c"
#include "ciphers/qapla.c"
#include "ciphers/spdi.c"
#include "ciphers/tpst.c"
#include "ciphers/hekago.c"

void usage() {
    printf("DarkCastle v1.1 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\ndark             256 bit\nuvajda           256 bit\nspock            256 bit\nhekago           256 bit\nspdi             256 bit\ntpst             256 bit\nqapla            256 bit\nzanderfish3      256 bit\nzanderfish3-ofb  256 bit\n\n");
    printf("Usage:\ncastle <algorithm> -e <input file> <output file> <public keyfile> <secret keyfile>\n");
    printf("castle <algorithm> -d <input file> <output file> <secret keyfile> <public keyfile>\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "KryptoMagickDarkCastleVersion1.0";
    int salt_len = 32;
    int kdf_iterations = 100000;
    int password_len = 64;
    int mask_bytes = 768;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish3_nonce_length = 32;
    int dark_nonce_length = 16;
    int uvajda_nonce_length = 16;
    int spock_nonce_length = 16;
    int qapla_nonce_length = 16;
    int spdi_nonce_length = 16;
    int tpst_nonce_length = 32;

    int zanderfish_key_length = 32;
    int zanderfish3_key_length = 32;
    int dark_key_length = 32;
    int uvajda_key_length = 32;
    int spock_key_length = 32;
    int qapla_key_length = 32;
    int spdi_key_length = 32;
    int tpst_key_length = 32;

    int dark_mac_length = 32;
    int zanderfish_mac_length = 32;
    int zanderfish3_mac_length = 32;
    int uvajda_mac_length = 32;
    int spock_mac_length = 32;
    int qapla_mac_length = 32;
    int spdi_mac_length = 32;
    int tpst_mac_length = 32;

    int dark_bufsize = 32768;
    int uvajda_bufsize = 32768;
    int zanderfish3_bufsize = 262144;
    int spock_bufsize = 131072;
    int qapla_bufsize = 262144;
    int spdi_bufsize = 131072;
    int tpst_bufsize = 131072;

    if (argc != 7) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *keyfile1_name, *keyfile2_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    keyfile1_name = argv[5];
    keyfile2_name = argv[6];
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);

    unsigned char * passphrase[64] = {0};
    printf("Enter secret key passphrase: ");
    scanf("%s", passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &save);

    if (strcmp(algorithm, "dark") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, dark_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, dark_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "uvajda") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            uvajda_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, uvajda_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            uvajda_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, uvajda_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "spock") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spock_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spock_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spock_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spock_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish3-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
    } 
    else if (strcmp(algorithm, "qapla") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            qapla_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, qapla_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            qapla_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, qapla_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "spdi") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spdiCBCEncrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spdi_key_length, spdi_nonce_length, spdi_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spdi_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spdiCBCDecrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spdi_key_length, spdi_nonce_length, spdi_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spdi_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "hekago") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            hekago_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spdi_key_length, spdi_nonce_length, spdi_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spdi_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            hekago_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spdi_key_length, spdi_nonce_length, spdi_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spdi_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "tpst") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            tpstCBCEncrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, tpst_key_length, tpst_nonce_length, tpst_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, tpst_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            tpstCBCDecrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, tpst_key_length, tpst_nonce_length, tpst_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, tpst_bufsize, passphrase);
        }
    }
    printf("\n");
    return 0;
}
