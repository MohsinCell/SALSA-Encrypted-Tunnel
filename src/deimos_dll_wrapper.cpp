#include "deimos_cipher.h"
#include <cstring>
#include <cstdlib>

extern "C" {

    struct EncryptedData {
        uint8_t* data;
        size_t length;
    };

    struct DecryptedData {
        char* data;
        size_t length;
        int success;
    };

    __declspec(dllexport) EncryptedData* deimos_encrypt(const char* plaintext, const char* password) {
        try {
            std::string plaintextStr(plaintext);
            std::string passwordStr(password);

            std::vector<uint8_t> ciphertext = deimosCipherEncrypt(plaintextStr, passwordStr);

            EncryptedData* result = (EncryptedData*)malloc(sizeof(EncryptedData));
            result->length = ciphertext.size();
            result->data = (uint8_t*)malloc(result->length);

            memcpy(result->data, ciphertext.data(), result->length);

            return result;
        } catch (const std::exception& e) {

            return nullptr;
        }
    }

    __declspec(dllexport) DecryptedData* deimos_decrypt(const uint8_t* ciphertext, size_t ciphertext_length, const char* password) {
        try {
            std::vector<uint8_t> ciphertextVec(ciphertext, ciphertext + ciphertext_length);
            std::string passwordStr(password);

            std::string plaintext = deimosCipherDecrypt(ciphertextVec, passwordStr);

            DecryptedData* result = (DecryptedData*)malloc(sizeof(DecryptedData));

            if (plaintext.substr(0, 6) == "Error:") {
                result->success = 0;
                result->length = plaintext.length();
                result->data = (char*)malloc(result->length + 1);
                strcpy(result->data, plaintext.c_str());
            } else {
                result->success = 1;
                result->length = plaintext.length();
                result->data = (char*)malloc(result->length + 1);
                strcpy(result->data, plaintext.c_str());
            }

            return result;
        } catch (const std::exception& e) {

            DecryptedData* result = (DecryptedData*)malloc(sizeof(DecryptedData));
            result->success = 0;
            result->length = strlen(e.what());
            result->data = (char*)malloc(result->length + 1);
            strcpy(result->data, e.what());
            return result;
        }
    }

    __declspec(dllexport) void free_encrypted_data(EncryptedData* data) {
        if (data) {
            if (data->data) {
                free(data->data);
            }
            free(data);
        }
    }

    __declspec(dllexport) void free_decrypted_data(DecryptedData* data) {
        if (data) {
            if (data->data) {
                free(data->data);
            }
            free(data);
        }
    }

    __declspec(dllexport) int deimos_init() {
        return sodium_init();
    }
}
