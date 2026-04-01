# s3fs-fuse fork with wolfSSL and Mbed TLS support

This repository contains a personal fork of `s3fs-fuse` with:

- internal crypto backend abstraction
- wolfSSL backend support
- Mbed TLS backend support
- OpenWrt-oriented packaging work maintained separately

## Status

- OpenSSL backend: working
- GnuTLS backend: working
- wolfSSL backend: working
- Mbed TLS backend: working

## Motivation

The goal is to make `s3fs-fuse` more suitable for embedded/OpenWrt environments where OpenSSL and GnuTLS are often less desirable than wolfSSL or Mbed TLS.

## Notes

This is not upstream.
The OpenWrt package is maintained separately as a patch series against upstream `s3fs-fuse` 1.97.
