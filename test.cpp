#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>
#include <cstring>

using namespace std;

int main(int argc, char *argv[]) {
#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
unsigned char ciphertext[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];
unsigned long long ciphertext_len;

sodium_init();
if (crypto_aead_aes256gcm_is_available() == 0) {
    abort(); /* Not available on this CPU */
}

crypto_aead_aes256gcm_keygen(key);
randombytes_buf(nonce, sizeof nonce);

crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                              MESSAGE, MESSAGE_LEN,
                              ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                              NULL, nonce, key);

unsigned char decrypted[MESSAGE_LEN];
unsigned long long decrypted_len;
int res;
if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
    (res = crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                  NULL,
                                  ciphertext, ciphertext_len,
                                  ADDITIONAL_DATA,
                                  ADDITIONAL_DATA_LEN,
                                  nonce, key)) != 0) {
    /* message forged! */
}
printf("%d", res);
printf("decrypted: ");
        for (auto&& c : decrypted){
            printf("%c",c);
        }
        printf("\n");

}