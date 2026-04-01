#ifndef S3FS_CRYPTO__H_
#define S3FS_CRYPTO__H_

#include <array>
#include <memory>
#include <string>
#include <sys/types.h>

typedef std::array<unsigned char, 16> md5_t;
typedef std::array<unsigned char, 32> sha256_t;

//
// in common_auth.cpp
//
std::string s3fs_get_content_md5(int fd);
std::string s3fs_sha256_hex_fd(int fd, off_t start, off_t size);

const char* s3fs_crypt_lib_name();

bool s3fs_init_global_ssl();
bool s3fs_destroy_global_ssl();

bool s3fs_init_crypt_mutex();
bool s3fs_destroy_crypt_mutex();

bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* result);
bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result);

std::unique_ptr<unsigned char[]> s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen);
std::unique_ptr<unsigned char[]> s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen);

bool s3fs_sha256(const unsigned char* data, size_t datalen, sha256_t* digest);
bool s3fs_sha256_fd(int fd, off_t start, off_t size, sha256_t* result);

#endif // S3FS_CRYPTO__H_