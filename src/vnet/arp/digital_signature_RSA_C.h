#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

int generate_rsa_signature(const unsigned char *message, size_t message_len, const char *private_key_path, unsigned char **signature, size_t *signature_len) {}

int verify_rsa_signature(const unsigned char *message, size_t message_len, const char *public_key_path, const unsigned char *signature, size_t signature_len) {}