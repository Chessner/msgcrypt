#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>
#include <cstring>

using namespace std;

int main(int argc, char *argv[]) {
   // #define MESSAGE (const unsigned char *) "test"
   // #define MESSAGE_LEN 4
    #define ADDITIONAL_DATA (const unsigned char *) "123456"
    #define ADDITIONAL_DATA_LEN 6

    string filename;
    int processingType = 0; // 0 = not set, 1 encode, -1 decode

    if(argc < 4){
        printf("Insufficient argument count. \n");
        return 1;
    }
    for(int i = 1; i < argc; i++){
        switch(i){
            case 1:
                if(strcmp(argv[i],"-key") != 0){
                    printf("Incorrect option: %s \n", argv[i]);
                    return 1;
                }
                break;
            case 2:
                filename = argv[i];
                break;
            case 3:
                if(strcmp(argv[i],"-enc") == 0 ){
                    processingType = 1;
                } else if (strcmp(argv[i],"-dec") == 0){
                    processingType = -1;
                } else {
                    printf("Incorrect option: %s \n", argv[i]);
                    return 1;
                }
                break;
            default: 
                printf("More options specified than necessary. Option: %s and following will be ignored.", argv[i]);
                break;
        }
    }

    ifstream myfile (filename);
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    crypto_aead_aes256gcm_keygen(key);

    if(myfile.is_open()){
        int i = 0;
        while(myfile.good() && i <= crypto_aead_aes256gcm_KEYBYTES){
            key[i] = myfile.get();
            i++;
        }
    } else {
        printf("Couldn't open file: \"%s\".\n", filename.c_str());
    }
    myfile.close();

    char *message_buffer = NULL;
    size_t len = 0;
    size_t MESSAGE_LEN = 0;
    MESSAGE_LEN = getline(&message_buffer, &len, stdin) - 1;
    
    const unsigned char * MESSAGE = (const unsigned char*) message_buffer;
    cout << "MESSAGE START:" << MESSAGE << ":MESSAGE END " << MESSAGE_LEN <<endl;

    int r = sodium_init();
    if (crypto_aead_aes256gcm_is_available() == 0) {
        abort(); 
    }

    printf("key: %s\n", key);

    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
   // randombytes_buf(nonce, sizeof nonce); 
   /*   nonce is random, which means it is not the same for en- and decryptionl. Either save in key.txt,
        pass as command line argument or ignore. I chose to ignore nonce in this implementation.
    */

    if(processingType == 1){
        printf("encoding...\n");
        unsigned char ciphertext[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];
        unsigned long long ciphertext_len;

        crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                                    MESSAGE, MESSAGE_LEN,
                                    ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                                    NULL, nonce, key);
     
        printf("bin: %s\n", ciphertext);

        int b64_len = sodium_base64_ENCODED_LEN(ciphertext_len, sodium_base64_VARIANT_ORIGINAL); 
        char b64[b64_len];
        sodium_bin2base64(b64, b64_len,
                            ciphertext, ciphertext_len,
                            sodium_base64_VARIANT_ORIGINAL);
      
        printf("b64: %s\n", b64);
    } else if (processingType == -1 ){
        printf("decoding...\n");
        size_t bin_maxlen = ((MESSAGE_LEN*10) / 4 * 3)/10;
        size_t* bin_len;
        unsigned char bin[bin_maxlen];
        int bres = 100;
        bres = sodium_base642bin(bin, bin_maxlen,
                    (const char*) MESSAGE, MESSAGE_LEN,
                    NULL, bin_len,
                    NULL, sodium_base64_VARIANT_ORIGINAL);
        printf("b642bin res:%d\n",bres);
        printf("bin: %s\n", bin);
        unsigned char decrypted[bin_maxlen - crypto_aead_aes256gcm_ABYTES];
        unsigned long long decrypted_len;
        int res = 100;
        if (bin_maxlen < crypto_aead_aes256gcm_ABYTES ||
            (res = crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                        NULL,
                                        bin, bin_maxlen, 
                                        ADDITIONAL_DATA,
                                        ADDITIONAL_DATA_LEN,
                                        nonce, key)) != 0) {
        }
        printf("decrypt res: %d\n", res);

        printf("decrypted: %s\n", decrypted);
    }
    return 0;
}
//gcc msgcrypt.cpp -lstdc++ -lsodium -o msgcrypt
//CFLAGS=$(pkg-config --cflags libsodium)
//LDFLAGS=$(pkg-config --libs libsodium)
