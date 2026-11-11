/*
 * XXTEA decrypt with the Cocos2d-x payload layout (plaintext length as a trailing LE word),
 * matching coconuts' ciphers.cocos_xxtea_decrypt so a blob encrypted in Python decrypts here.
 * Signature matches cocos2d-x external/xxtea/xxtea.h.
 */
#include <stdlib.h>
#include <string.h>
#include "xxtea_min.h"

#define XXTEA_DELTA 0x9e3779b9u
#define MX ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))

static void xxtea_block_decrypt(unsigned int *v, int n_words, const unsigned int *k)
{
    unsigned int y, z, sum;
    unsigned int e;
    int p, q, n = n_words - 1;

    if (n < 1) return;
    q = 6 + 52 / (n + 1);
    sum = (unsigned int)q * XXTEA_DELTA;
    y = v[0];
    while (sum != 0) {
        e = (sum >> 2) & 3;
        for (p = n; p > 0; p--) {
            z = v[p - 1];
            y = v[p] -= MX;
        }
        z = v[n];
        p = 0;
        y = v[0] -= MX;
        sum -= XXTEA_DELTA;
    }
}

unsigned char *xxtea_decrypt(unsigned char *data, xxtea_long len,
                             unsigned char *key, xxtea_long key_len,
                             xxtea_long *out_len)
{
    unsigned char key16[16];
    unsigned int *v;
    unsigned char *out;
    xxtea_long n_words, m;

    if (out_len) *out_len = 0;
    if (!data || len < 8 || (len % 4) != 0) return NULL;

    /* Cocos pads a short key with zeros and truncates a long one. */
    memset(key16, 0, sizeof key16);
    memcpy(key16, key, key_len < 16 ? key_len : 16);

    n_words = len / 4;
    v = (unsigned int *)malloc(len);
    if (!v) return NULL;
    memcpy(v, data, len);
    xxtea_block_decrypt(v, (int)n_words, (const unsigned int *)key16);

    /* Plaintext length is the trailing word. */
    memcpy(&m, (unsigned char *)v + len - 4, 4);
    if (m < len - 7 || m > len - 4) {   /* wrong key or not this format */
        free(v);
        return NULL;
    }

    out = (unsigned char *)malloc(m + 1);
    if (!out) {
        free(v);
        return NULL;
    }
    memcpy(out, v, m);
    out[m] = '\0';
    free(v);
    if (out_len) *out_len = m;
    return out;
}
