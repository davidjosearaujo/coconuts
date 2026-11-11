#ifndef XXTEA_MIN_H
#define XXTEA_MIN_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int xxtea_long;

unsigned char *xxtea_decrypt(unsigned char *data, xxtea_long len,
                             unsigned char *key, xxtea_long key_len,
                             xxtea_long *out_len);

#ifdef __cplusplus
}
#endif
#endif
