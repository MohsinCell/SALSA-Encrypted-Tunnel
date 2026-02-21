#include "deimos_cipher.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <vector>
#include <array>
#include <cstring>
#include <iostream>

std::array<std::vector<uint8_t>, 3> deriveKeysHKDF(const std::string &password, const std::vector<uint8_t> &salt)
{
    std::array<std::vector<uint8_t>, 3> keys;

    for (int i = 0; i < 3; ++i)
    {
        keys[i].resize(crypto_stream_xchacha20_KEYBYTES);
    }

    std::vector<uint8_t> prk(64);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
    {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for HKDF");
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_blake2b512()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, reinterpret_cast<const unsigned char *>(password.data()), password.size()) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF extraction failed");
    }

    size_t prk_len = prk.size();
    if (EVP_PKEY_derive(pctx, prk.data(), &prk_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF PRK derivation failed");
    }
    EVP_PKEY_CTX_free(pctx);

    for (int i = 0; i < 3; ++i)
    {
        std::vector<uint8_t> info = {'K', 'E', 'Y', static_cast<uint8_t>(i)};
        EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!key_ctx)
        {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX for HKDF expansion");
        }

        if (EVP_PKEY_derive_init(key_ctx) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(key_ctx, EVP_blake2b512()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(key_ctx, salt.data(), salt.size()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(key_ctx, prk.data(), prk_len) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(key_ctx, info.data(), info.size()) <= 0)
        {
            EVP_PKEY_CTX_free(key_ctx);
            throw std::runtime_error("HKDF expansion failed");
        }

        size_t key_len = keys[i].size();
        if (EVP_PKEY_derive(key_ctx, keys[i].data(), &key_len) <= 0)
        {
            EVP_PKEY_CTX_free(key_ctx);
            throw std::runtime_error("HKDF key derivation failed");
        }
        EVP_PKEY_CTX_free(key_ctx);
    }

    return keys;
}

std::vector<uint8_t> generateHMAC(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key)
{
    std::array<uint8_t, SHA256_DIGEST_LENGTH> hmac;
    unsigned int len = SHA256_DIGEST_LENGTH;
    if (!HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &len))
    {
        throw std::runtime_error("HMAC generation failed");
    }
    return std::vector<uint8_t>(hmac.begin(), hmac.begin() + len);
}

std::vector<uint8_t> deimosCipherEncrypt(const std::string &plaintext, const std::string &password)
{
    std::vector<uint8_t> salt(32);
    randombytes_buf(salt.data(), salt.size());

    auto keys = deriveKeysHKDF(password, salt);

    if (keys[0].size() != crypto_stream_xchacha20_KEYBYTES)
    {
        throw std::runtime_error("Invalid key size for XChaCha20");
    }

    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());

    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> keystream(plaintextVec.size());
    crypto_stream_xchacha20(keystream.data(), keystream.size(), nonce, keys[0].data());

    for (size_t i = 0; i < plaintextVec.size(); ++i)
    {
        plaintextVec[i] ^= keystream[i];
    }

    std::vector<uint8_t> hmac = generateHMAC(plaintextVec, keys[2]);

    std::vector<uint8_t> ciphertext;
    ciphertext.insert(ciphertext.end(), salt.begin(), salt.end());
    ciphertext.insert(ciphertext.end(), nonce, nonce + crypto_stream_xchacha20_NONCEBYTES);
    ciphertext.insert(ciphertext.end(), plaintextVec.begin(), plaintextVec.end());
    ciphertext.insert(ciphertext.end(), hmac.begin(), hmac.end());

    return ciphertext;
}

std::string deimosCipherDecrypt(const std::vector<uint8_t> &ciphertext, const std::string &password)
{
    if (ciphertext.size() < 32 + crypto_stream_xchacha20_NONCEBYTES + SHA256_DIGEST_LENGTH)
    {
        return "Error: Ciphertext too short!";
    }

    std::vector<uint8_t> salt(ciphertext.begin(), ciphertext.begin() + 32);
    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    std::memcpy(nonce, ciphertext.data() + 32, crypto_stream_xchacha20_NONCEBYTES);

    std::vector<uint8_t> encryptedData(ciphertext.begin() + 32 + crypto_stream_xchacha20_NONCEBYTES,
                                       ciphertext.end() - SHA256_DIGEST_LENGTH);
    std::vector<uint8_t> receivedHMAC(ciphertext.end() - SHA256_DIGEST_LENGTH, ciphertext.end());

    auto keys = deriveKeysHKDF(password, salt);

    if (keys[0].size() != crypto_stream_xchacha20_KEYBYTES)
    {
        throw std::runtime_error("Invalid key size for XChaCha20");
    }

    std::vector<uint8_t> calculatedHMAC = generateHMAC(encryptedData, keys[2]);

    if (!std::equal(receivedHMAC.begin(), receivedHMAC.end(), calculatedHMAC.begin()))
    {
        return "Error: Integrity check failed!";
    }

    std::vector<uint8_t> keystream(encryptedData.size());
    crypto_stream_xchacha20(keystream.data(), keystream.size(), nonce, keys[0].data());

    for (size_t i = 0; i < encryptedData.size(); ++i)
    {
        encryptedData[i] ^= keystream[i];
    }

    return std::string(encryptedData.begin(), encryptedData.end());
}
