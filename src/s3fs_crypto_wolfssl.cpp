#ifdef __clang__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

/*
 * OpenSSL compatibility layer.
 * Requires wolfSSL to be built with:
 *   --enable-opensslextra
 * or OPENSSL_EXTRA
 */
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/md5.h>
#include <wolfssl/openssl/crypto.h>
#include <wolfssl/openssl/err.h>

#include "s3fs_crypto.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
const char* s3fs_crypt_lib_name()
{
    static constexpr char version[] = "wolfSSL";
    return version;
}

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl()
{
    /*
     * wolfSSL recommends wolfSSL_Init() / wolfSSL_Cleanup().
     * The OpenSSL compatibility wrappers exist, but using the native
     * global init/cleanup is cleaner here.
     */
    int ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        S3FS_PRN_ERR("wolfSSL_Init failed: %d", ret);
        return false;
    }
    return true;
}

bool s3fs_destroy_global_ssl()
{
    int ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS) {
        S3FS_PRN_ERR("wolfSSL_Cleanup failed: %d", ret);
        return false;
    }
    return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
bool s3fs_init_crypt_mutex()
{
    /*
     * Unlike legacy OpenSSL integration, wolfSSL is documented as
     * thread-safe by design and does not require the old global
     * CRYPTO_set_locking_callback() style setup.
     */
    return true;
}

bool s3fs_destroy_crypt_mutex()
{
    return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------
static std::unique_ptr<unsigned char[]> s3fs_HMAC_RAW(
    const void*          key,
    size_t               keylen,
    const unsigned char* data,
    size_t               datalen,
    unsigned int*        digestlen,
    bool                 is_sha256)
{
    if (!key || !data || !digestlen) {
        return nullptr;
    }

    *digestlen = EVP_MAX_MD_SIZE * sizeof(unsigned char);
    auto digest = std::make_unique<unsigned char[]>(*digestlen);

    const EVP_MD* md = is_sha256 ? EVP_sha256() : EVP_sha1();
    if (!md) {
        S3FS_PRN_ERR("EVP digest selection failed");
        return nullptr;
    }

    unsigned char* ret = HMAC(
        md,
        key,
        static_cast<int>(keylen),
        data,
        datalen,
        digest.get(),
        digestlen
    );

    if (!ret) {
        S3FS_PRN_ERR("HMAC computation failed");
        return nullptr;
    }

    return digest;
}

std::unique_ptr<unsigned char[]> s3fs_HMAC(
    const void*          key,
    size_t               keylen,
    const unsigned char* data,
    size_t               datalen,
    unsigned int*        digestlen)
{
    return s3fs_HMAC_RAW(key, keylen, data, datalen, digestlen, false);
}

std::unique_ptr<unsigned char[]> s3fs_HMAC256(
    const void*          key,
    size_t               keylen,
    const unsigned char* data,
    size_t               datalen,
    unsigned int*        digestlen)
{
    return s3fs_HMAC_RAW(key, keylen, data, datalen, digestlen, true);
}

//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* digest)
{
    if (!data || !digest) {
        return false;
    }

    unsigned int digestlen = static_cast<unsigned int>(digest->size());

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!mdctx) {
        S3FS_PRN_ERR("EVP_MD_CTX_new failed");
        return false;
    }

    if (EVP_DigestInit_ex(mdctx.get(), EVP_md5(), nullptr) != 1) {
        S3FS_PRN_ERR("EVP_DigestInit_ex(EVP_md5) failed");
        return false;
    }

    if (EVP_DigestUpdate(mdctx.get(), data, datalen) != 1) {
        S3FS_PRN_ERR("EVP_DigestUpdate failed");
        return false;
    }

    if (EVP_DigestFinal_ex(mdctx.get(), digest->data(), &digestlen) != 1) {
        S3FS_PRN_ERR("EVP_DigestFinal_ex failed");
        return false;
    }

    return digestlen == digest->size();
}

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    if (fd == -1 || !result) {
        return false;
    }

    if (size == -1) {
        struct stat st;
        if (fstat(fd, &st) == -1) {
            S3FS_PRN_ERR("fstat error(%d)", errno);
            return false;
        }
        size = st.st_size;
    }

    unsigned int digestlen = static_cast<unsigned int>(result->size());

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!mdctx) {
        S3FS_PRN_ERR("EVP_MD_CTX_new failed");
        return false;
    }

    if (EVP_DigestInit_ex(mdctx.get(), EVP_md5(), nullptr) != 1) {
        S3FS_PRN_ERR("EVP_DigestInit_ex(EVP_md5) failed");
        return false;
    }

    for (off_t total = 0; total < size; ) {
        std::array<unsigned char, 512> buf{};
        off_t want = std::min<off_t>(static_cast<off_t>(buf.size()), size - total);
        off_t bytes = pread(fd, buf.data(), static_cast<size_t>(want), start + total);

        if (bytes == 0) {
            break;
        }
        if (bytes < 0) {
            S3FS_PRN_ERR("file read error(%d)", errno);
            return false;
        }

        if (EVP_DigestUpdate(mdctx.get(), buf.data(), static_cast<size_t>(bytes)) != 1) {
            S3FS_PRN_ERR("EVP_DigestUpdate failed");
            return false;
        }

        total += bytes;
    }

    if (EVP_DigestFinal_ex(mdctx.get(), result->data(), &digestlen) != 1) {
        S3FS_PRN_ERR("EVP_DigestFinal_ex failed");
        return false;
    }

    return digestlen == result->size();
}

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
bool s3fs_sha256(const unsigned char* data, size_t datalen, sha256_t* digest)
{
    if (!data || !digest) {
        return false;
    }

    unsigned int digestlen = static_cast<unsigned int>(digest->size());

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!mdctx) {
        S3FS_PRN_ERR("EVP_MD_CTX_new failed");
        return false;
    }

    if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1) {
        S3FS_PRN_ERR("EVP_DigestInit_ex(EVP_sha256) failed");
        return false;
    }

    if (EVP_DigestUpdate(mdctx.get(), data, datalen) != 1) {
        S3FS_PRN_ERR("EVP_DigestUpdate failed");
        return false;
    }

    if (EVP_DigestFinal_ex(mdctx.get(), digest->data(), &digestlen) != 1) {
        S3FS_PRN_ERR("EVP_DigestFinal_ex failed");
        return false;
    }

    return digestlen == digest->size();
}

bool s3fs_sha256_fd(int fd, off_t start, off_t size, sha256_t* result)
{
    if (fd == -1 || !result) {
        return false;
    }

    if (size == -1) {
        struct stat st;
        if (fstat(fd, &st) == -1) {
            S3FS_PRN_ERR("fstat error(%d)", errno);
            return false;
        }
        size = st.st_size;
    }

    unsigned int digestlen = static_cast<unsigned int>(result->size());

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!mdctx) {
        S3FS_PRN_ERR("EVP_MD_CTX_new failed");
        return false;
    }

    if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1) {
        S3FS_PRN_ERR("EVP_DigestInit_ex(EVP_sha256) failed");
        return false;
    }

    for (off_t total = 0; total < size; ) {
        std::array<unsigned char, 512> buf{};
        off_t want = std::min<off_t>(static_cast<off_t>(buf.size()), size - total);
        off_t bytes = pread(fd, buf.data(), static_cast<size_t>(want), start + total);

        if (bytes == 0) {
            break;
        }
        if (bytes < 0) {
            S3FS_PRN_ERR("file read error(%d)", errno);
            return false;
        }

        if (EVP_DigestUpdate(mdctx.get(), buf.data(), static_cast<size_t>(bytes)) != 1) {
            S3FS_PRN_ERR("EVP_DigestUpdate failed");
            return false;
        }

        total += bytes;
    }

    if (EVP_DigestFinal_ex(mdctx.get(), result->data(), &digestlen) != 1) {
        S3FS_PRN_ERR("EVP_DigestFinal_ex failed");
        return false;
    }

    return digestlen == result->size();
}