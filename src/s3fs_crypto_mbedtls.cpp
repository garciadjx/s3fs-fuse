#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>

#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <mbedtls/platform_util.h>

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#endif

#include "s3fs_crypto.h"
#include "s3fs_logger.h"

namespace
{
#if defined(MBEDTLS_PLATFORM_C)
    mbedtls_platform_context g_mbedtls_platform_ctx{};
    bool g_mbedtls_platform_ready = false;
#endif

    void log_mbedtls_error(const char* where, int ret)
    {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        S3FS_PRN_ERR("%s failed: ret=%d (%s)", where, ret, errbuf);
    }

    const mbedtls_md_info_t* get_md_info(mbedtls_md_type_t md_type, const char* where)
    {
        const mbedtls_md_info_t* info = mbedtls_md_info_from_type(md_type);
        if (!info) {
            S3FS_PRN_ERR("%s failed: digest info not available for type=%d",
                         where, static_cast<int>(md_type));
        }
        return info;
    }

    bool digest_buffer(const unsigned char* data,
                       size_t datalen,
                       mbedtls_md_type_t md_type,
                       unsigned char* out,
                       size_t expected_len,
                       const char* where)
    {
        if (!data || !out) {
            S3FS_PRN_ERR("%s failed: invalid input", where);
            return false;
        }

        const mbedtls_md_info_t* info = get_md_info(md_type, where);
        if (!info) {
            return false;
        }

        const size_t actual_len = mbedtls_md_get_size(info);
        if (actual_len != expected_len) {
            S3FS_PRN_ERR("%s failed: digest size mismatch, expected=%zu actual=%zu",
                         where, expected_len, actual_len);
            return false;
        }

        const int ret = mbedtls_md(info, data, datalen, out);
        if (ret != 0) {
            log_mbedtls_error(where, ret);
            return false;
        }

        return true;
    }

    bool digest_fd(int fd,
                   off_t start,
                   off_t size,
                   mbedtls_md_type_t md_type,
                   unsigned char* out,
                   size_t expected_len,
                   const char* where)
    {
        if (fd == -1 || !out) {
            S3FS_PRN_ERR("%s failed: invalid input", where);
            return false;
        }

        if (size == -1) {
            struct stat st;
            if (fstat(fd, &st) == -1) {
                S3FS_PRN_ERR("%s failed: fstat error(%d)", where, errno);
                return false;
            }
            size = st.st_size;
        }

        const mbedtls_md_info_t* info = get_md_info(md_type, where);
        if (!info) {
            return false;
        }

        const size_t actual_len = mbedtls_md_get_size(info);
        if (actual_len != expected_len) {
            S3FS_PRN_ERR("%s failed: digest size mismatch, expected=%zu actual=%zu",
                         where, expected_len, actual_len);
            return false;
        }

        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);

        int ret = mbedtls_md_setup(&ctx, info, 0);
        if (ret != 0) {
            log_mbedtls_error("mbedtls_md_setup", ret);
            mbedtls_md_free(&ctx);
            return false;
        }

        ret = mbedtls_md_starts(&ctx);
        if (ret != 0) {
            log_mbedtls_error("mbedtls_md_starts", ret);
            mbedtls_md_free(&ctx);
            return false;
        }

        for (off_t total = 0; total < size; ) {
            std::array<unsigned char, 512> buf{};
            off_t want  = std::min<off_t>(static_cast<off_t>(buf.size()), size - total);
            off_t bytes = pread(fd, buf.data(), static_cast<size_t>(want), start + total);

            if (bytes == 0) {
                break;
            }
            if (bytes < 0) {
                S3FS_PRN_ERR("%s failed: file read error(%d)", where, errno);
                mbedtls_md_free(&ctx);
                return false;
            }

            ret = mbedtls_md_update(&ctx, buf.data(), static_cast<size_t>(bytes));
            if (ret != 0) {
                log_mbedtls_error("mbedtls_md_update", ret);
                mbedtls_md_free(&ctx);
                return false;
            }

            total += bytes;
        }

        ret = mbedtls_md_finish(&ctx, out);
        if (ret != 0) {
            log_mbedtls_error("mbedtls_md_finish", ret);
            mbedtls_md_free(&ctx);
            return false;
        }

        mbedtls_md_free(&ctx);
        return true;
    }

    std::unique_ptr<unsigned char[]> hmac_raw(const void* key,
                                              size_t keylen,
                                              const unsigned char* data,
                                              size_t datalen,
                                              unsigned int* digestlen,
                                              mbedtls_md_type_t md_type,
                                              const char* where)
    {
        if (!key || !data || !digestlen) {
            S3FS_PRN_ERR("%s failed: invalid input", where);
            return nullptr;
        }

        const mbedtls_md_info_t* info = get_md_info(md_type, where);
        if (!info) {
            return nullptr;
        }

        const size_t out_len = mbedtls_md_get_size(info);
        if (out_len == 0 || out_len > MBEDTLS_MD_MAX_SIZE) {
            S3FS_PRN_ERR("%s failed: invalid digest size %zu", where, out_len);
            return nullptr;
        }

        auto digest = std::make_unique<unsigned char[]>(out_len);

        const int ret = mbedtls_md_hmac(info,
                                        static_cast<const unsigned char*>(key), keylen,
                                        data, datalen,
                                        digest.get());
        if (ret != 0) {
            log_mbedtls_error(where, ret);
            return nullptr;
        }

        *digestlen = static_cast<unsigned int>(out_len);
        return digest;
    }
} // namespace

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
const char* s3fs_crypt_lib_name()
{
    static constexpr char version[] = "Mbed TLS";
    return version;
}

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl()
{
#if defined(MBEDTLS_PLATFORM_C)
    const int ret = mbedtls_platform_setup(&g_mbedtls_platform_ctx);
    if (ret != 0) {
        log_mbedtls_error("mbedtls_platform_setup", ret);
        return false;
    }
    g_mbedtls_platform_ready = true;
#endif
    return true;
}

bool s3fs_destroy_global_ssl()
{
#if defined(MBEDTLS_PLATFORM_C)
    if (g_mbedtls_platform_ready) {
        mbedtls_platform_teardown(&g_mbedtls_platform_ctx);
        g_mbedtls_platform_ready = false;
    }
#endif
    return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
bool s3fs_init_crypt_mutex()
{
    return true;
}

bool s3fs_destroy_crypt_mutex()
{
    return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------
std::unique_ptr<unsigned char[]> s3fs_HMAC(const void* key,
                                           size_t keylen,
                                           const unsigned char* data,
                                           size_t datalen,
                                           unsigned int* digestlen)
{
    return hmac_raw(key, keylen, data, datalen, digestlen,
                    MBEDTLS_MD_SHA1, "mbedtls_md_hmac(SHA1)");
}

std::unique_ptr<unsigned char[]> s3fs_HMAC256(const void* key,
                                              size_t keylen,
                                              const unsigned char* data,
                                              size_t datalen,
                                              unsigned int* digestlen)
{
    return hmac_raw(key, keylen, data, datalen, digestlen,
                    MBEDTLS_MD_SHA256, "mbedtls_md_hmac(SHA256)");
}

//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* digest)
{
    return digest_buffer(data, datalen,
                         MBEDTLS_MD_MD5,
                         digest ? digest->data() : nullptr,
                         digest ? digest->size() : 0,
                         "mbedtls_md(MD5)");
}

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    return digest_fd(fd, start, size,
                     MBEDTLS_MD_MD5,
                     result ? result->data() : nullptr,
                     result ? result->size() : 0,
                     "mbedtls_md_* fd(MD5)");
}

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
bool s3fs_sha256(const unsigned char* data, size_t datalen, sha256_t* digest)
{
    return digest_buffer(data, datalen,
                         MBEDTLS_MD_SHA256,
                         digest ? digest->data() : nullptr,
                         digest ? digest->size() : 0,
                         "mbedtls_md(SHA256)");
}

bool s3fs_sha256_fd(int fd, off_t start, off_t size, sha256_t* result)
{
    return digest_fd(fd, start, size,
                     MBEDTLS_MD_SHA256,
                     result ? result->data() : nullptr,
                     result ? result->size() : 0,
                     "mbedtls_md_* fd(SHA256)");
}