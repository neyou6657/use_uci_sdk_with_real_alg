#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#include <string.h>

#include "../../alg/experimental_pq/cross-rsdp-128-small_clean/api.h"
#include "../../alg/experimental_pq/sntrup761_clean/api.h"

#define PQV_PROVIDER_NAME "pqvariantprovider"
#define PQV_PROPERTIES "provider=pqvariantprovider"

#define PQV_MAX_PUBLIC_KEY_LEN PQCLEAN_SNTRUP761_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQV_MAX_PRIVATE_KEY_LEN PQCLEAN_SNTRUP761_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQV_MAX_CIPHERTEXT_LEN PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQV_MAX_SECRET_LEN PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES
#define PQV_MAX_SIGNATURE_LEN PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_BYTES

typedef enum {
    PQV_KIND_KEM = 1,
    PQV_KIND_SIGNATURE = 2
} PQV_KIND;

typedef struct pqv_alg_def_st PQV_ALG_DEF;

typedef struct {
    const PQV_ALG_DEF *alg;
    unsigned char pub[PQV_MAX_PUBLIC_KEY_LEN];
    unsigned char priv[PQV_MAX_PRIVATE_KEY_LEN];
    int has_pub;
    int has_priv;
} PQV_KEYDATA;

typedef struct {
    void *provctx;
    int selection;
    const PQV_ALG_DEF *alg;
} PQV_GEN_CTX;

typedef struct {
    void *provctx;
    PQV_KEYDATA *key;
} PQV_KEM_CTX;

typedef struct {
    void *provctx;
    PQV_KEYDATA *key;
    unsigned char *msg;
    size_t msg_len;
    size_t msg_cap;
} PQV_SIG_CTX;

typedef struct {
    const OSSL_CORE_HANDLE *handle;
} PQV_PROVIDER_CTX;

struct pqv_alg_def_st {
    const char *name;
    PQV_KIND kind;
    size_t public_key_len;
    size_t private_key_len;
    size_t max_output_len;
    int security_bits;
    int (*keypair)(unsigned char *pub, unsigned char *priv);
    int (*kem_enc)(unsigned char *ct, unsigned char *secret, const unsigned char *pub);
    int (*kem_dec)(unsigned char *secret, const unsigned char *ct, const unsigned char *priv);
    int (*sign)(unsigned char *sig, size_t *siglen,
                const unsigned char *msg, size_t msglen, const unsigned char *priv);
    int (*verify)(const unsigned char *sig, size_t siglen,
                  const unsigned char *msg, size_t msglen, const unsigned char *pub);
};

static const PQV_ALG_DEF pqv_sntrup761 = {
    PQCLEAN_SNTRUP761_CLEAN_CRYPTO_ALGNAME,
    PQV_KIND_KEM,
    PQCLEAN_SNTRUP761_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SNTRUP761_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    128,
    PQCLEAN_SNTRUP761_CLEAN_crypto_kem_keypair,
    PQCLEAN_SNTRUP761_CLEAN_crypto_kem_enc,
    PQCLEAN_SNTRUP761_CLEAN_crypto_kem_dec,
    NULL,
    NULL
};

static const PQV_ALG_DEF pqv_cross_rsdp_128_small = {
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_ALGNAME,
    PQV_KIND_SIGNATURE,
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_BYTES,
    128,
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_crypto_sign_keypair,
    NULL,
    NULL,
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_crypto_sign_signature,
    PQCLEAN_CROSSRSDP128SMALL_CLEAN_crypto_sign_verify
};

static const OSSL_PARAM pqv_empty_params[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM pqv_key_import_export_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pqv_key_gettable_params_def[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pqv_provider_gettable_params_def[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_uint(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static int pqv_wants_public(int selection)
{
    return selection == 0 ||
           selection == OSSL_KEYMGMT_SELECT_KEYPAIR ||
           (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int pqv_wants_private(int selection)
{
    return selection == 0 ||
           selection == OSSL_KEYMGMT_SELECT_KEYPAIR ||
           (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static void *pqv_key_new_common(void *provctx, const PQV_ALG_DEF *alg)
{
    PQV_KEYDATA *key;

    (void)provctx;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key != NULL) {
        key->alg = alg;
    }
    return key;
}

static void pqv_key_free(void *keydata)
{
    OPENSSL_clear_free(keydata, sizeof(PQV_KEYDATA));
}

static void *pqv_sntrup761_key_new(void *provctx)
{
    return pqv_key_new_common(provctx, &pqv_sntrup761);
}

static void *pqv_cross_key_new(void *provctx)
{
    return pqv_key_new_common(provctx, &pqv_cross_rsdp_128_small);
}

static void *pqv_gen_init_common(void *provctx, int selection,
                                 const OSSL_PARAM params[],
                                 const PQV_ALG_DEF *alg)
{
    PQV_GEN_CTX *ctx;

    (void)params;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->selection = selection;
    ctx->alg = alg;
    return ctx;
}

static void *pqv_sntrup761_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return pqv_gen_init_common(provctx, selection, params, &pqv_sntrup761);
}

static void *pqv_cross_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return pqv_gen_init_common(provctx, selection, params, &pqv_cross_rsdp_128_small);
}

static int pqv_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void)genctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *pqv_gen_settable_params(void *genctx, void *provctx)
{
    (void)genctx;
    (void)provctx;
    return pqv_empty_params;
}

static void *pqv_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    PQV_GEN_CTX *ctx = (PQV_GEN_CTX *)genctx;
    PQV_KEYDATA *key;

    (void)cb;
    (void)cbarg;

    if (ctx == NULL || ctx->alg == NULL) {
        return NULL;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        return NULL;
    }
    key->alg = ctx->alg;

    if (ctx->alg->keypair(key->pub, key->priv) != 0) {
        OPENSSL_clear_free(key, sizeof(*key));
        return NULL;
    }

    key->has_pub = pqv_wants_public(ctx->selection);
    key->has_priv = pqv_wants_private(ctx->selection);

    if (!key->has_pub) {
        OPENSSL_cleanse(key->pub, sizeof(key->pub));
    }
    if (!key->has_priv) {
        OPENSSL_cleanse(key->priv, sizeof(key->priv));
    }
    return key;
}

static void pqv_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static int pqv_key_get_params(void *keydata, OSSL_PARAM params[])
{
    PQV_KEYDATA *key = (PQV_KEYDATA *)keydata;
    OSSL_PARAM *p;

    if (key == NULL || key->alg == NULL) {
        return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, (int)(key->alg->public_key_len * 8))) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
        !OSSL_PARAM_set_int(p, key->alg->security_bits)) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, key->alg->max_output_len)) {
        return 0;
    }

    if (key->has_pub) {
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL &&
            !OSSL_PARAM_set_octet_string(p, key->pub, key->alg->public_key_len)) {
            return 0;
        }
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL &&
            !OSSL_PARAM_set_octet_string(p, key->pub, key->alg->public_key_len)) {
            return 0;
        }
    }

    if (key->has_priv &&
        (p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, key->priv, key->alg->private_key_len)) {
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *pqv_key_gettable_params(void *provctx)
{
    (void)provctx;
    return pqv_key_gettable_params_def;
}

static int pqv_key_has(const void *keydata, int selection)
{
    const PQV_KEYDATA *key = (const PQV_KEYDATA *)keydata;

    if (key == NULL || key->alg == NULL) {
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_pub) {
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !key->has_priv) {
        return 0;
    }
    return 1;
}

static int pqv_key_validate(const void *keydata, int selection, int checktype)
{
    (void)checktype;
    return pqv_key_has(keydata, selection);
}

static int pqv_key_match(const void *keydata1, const void *keydata2, int selection)
{
    const PQV_KEYDATA *a = (const PQV_KEYDATA *)keydata1;
    const PQV_KEYDATA *b = (const PQV_KEYDATA *)keydata2;

    if (a == NULL || b == NULL || a->alg != b->alg) {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!a->has_pub || !b->has_pub ||
            memcmp(a->pub, b->pub, a->alg->public_key_len) != 0) {
            return 0;
        }
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!a->has_priv || !b->has_priv ||
            memcmp(a->priv, b->priv, a->alg->private_key_len) != 0) {
            return 0;
        }
    }
    return 1;
}

static const char *pqv_sntrup761_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_KEM) {
        return pqv_sntrup761.name;
    }
    return NULL;
}

static const char *pqv_cross_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE) {
        return pqv_cross_rsdp_128_small.name;
    }
    return NULL;
}

static int pqv_key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    PQV_KEYDATA *key = (PQV_KEYDATA *)keydata;
    const OSSL_PARAM *p;
    const void *buf = NULL;
    size_t len = 0;

    if (key == NULL || key->alg == NULL || params == NULL) {
        return 0;
    }

    if (pqv_wants_public(selection)) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p == NULL ||
            !OSSL_PARAM_get_octet_string_ptr(p, &buf, &len) ||
            len != key->alg->public_key_len) {
            return 0;
        }
        memcpy(key->pub, buf, len);
        key->has_pub = 1;
    }

    if (pqv_wants_private(selection)) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p == NULL ||
            !OSSL_PARAM_get_octet_string_ptr(p, &buf, &len) ||
            len != key->alg->private_key_len) {
            return 0;
        }
        memcpy(key->priv, buf, len);
        key->has_priv = 1;
    }

    return 1;
}

static const OSSL_PARAM *pqv_key_import_types(int selection)
{
    (void)selection;
    return pqv_key_import_export_params;
}

static int pqv_key_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    PQV_KEYDATA *key = (PQV_KEYDATA *)keydata;
    OSSL_PARAM params[3];
    size_t n = 0;

    if (key == NULL || key->alg == NULL || cb == NULL) {
        return 0;
    }

    if (pqv_wants_public(selection) && key->has_pub) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, key->pub, key->alg->public_key_len);
    }
    if (pqv_wants_private(selection) && key->has_priv) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, key->priv, key->alg->private_key_len);
    }
    params[n] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static const OSSL_PARAM *pqv_key_export_types(int selection)
{
    (void)selection;
    return pqv_key_import_export_params;
}

static void *pqv_key_dup(const void *keydata_from, int selection)
{
    const PQV_KEYDATA *src = (const PQV_KEYDATA *)keydata_from;
    PQV_KEYDATA *dst;

    if (src == NULL || src->alg == NULL) {
        return NULL;
    }

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        return NULL;
    }
    dst->alg = src->alg;

    if (pqv_wants_public(selection) && src->has_pub) {
        memcpy(dst->pub, src->pub, src->alg->public_key_len);
        dst->has_pub = 1;
    }
    if (pqv_wants_private(selection) && src->has_priv) {
        memcpy(dst->priv, src->priv, src->alg->private_key_len);
        dst->has_priv = 1;
    }
    return dst;
}

static void *pqv_kem_newctx(void *provctx)
{
    PQV_KEM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }
    return ctx;
}

static int pqv_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQV_KEM_CTX *ctx = (PQV_KEM_CTX *)vctx;
    PQV_KEYDATA *key = (PQV_KEYDATA *)vkey;

    (void)params;

    if (ctx == NULL || key == NULL || key->alg != &pqv_sntrup761 || !key->has_pub) {
        return 0;
    }
    ctx->key = key;
    return 1;
}

static int pqv_kem_encapsulate(void *vctx,
                               unsigned char *out, size_t *outlen,
                               unsigned char *secret, size_t *secretlen)
{
    PQV_KEM_CTX *ctx = (PQV_KEM_CTX *)vctx;
    size_t outcap;
    size_t secretcap;

    if (ctx == NULL || ctx->key == NULL || outlen == NULL || secretlen == NULL) {
        return 0;
    }

    outcap = *outlen;
    secretcap = *secretlen;
    *outlen = PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    *secretlen = PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES;

    if (out == NULL || secret == NULL) {
        return 1;
    }
    if (outcap < *outlen || secretcap < *secretlen) {
        return 0;
    }
    return pqv_sntrup761.kem_enc(out, secret, ctx->key->pub) == 0;
}

static int pqv_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQV_KEM_CTX *ctx = (PQV_KEM_CTX *)vctx;
    PQV_KEYDATA *key = (PQV_KEYDATA *)vkey;

    (void)params;

    if (ctx == NULL || key == NULL || key->alg != &pqv_sntrup761 || !key->has_priv) {
        return 0;
    }
    ctx->key = key;
    return 1;
}

static int pqv_kem_decapsulate(void *vctx,
                               unsigned char *out, size_t *outlen,
                               const unsigned char *in, size_t inlen)
{
    PQV_KEM_CTX *ctx = (PQV_KEM_CTX *)vctx;
    size_t outcap;

    if (ctx == NULL || ctx->key == NULL || outlen == NULL || in == NULL) {
        return 0;
    }
    if (inlen != PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
        return 0;
    }

    outcap = *outlen;
    *outlen = PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES;
    if (out == NULL) {
        return 1;
    }
    if (outcap < *outlen) {
        return 0;
    }
    return pqv_sntrup761.kem_dec(out, in, ctx->key->priv) == 0;
}

static void pqv_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static void *pqv_kem_dupctx(void *vctx)
{
    PQV_KEM_CTX *src = (PQV_KEM_CTX *)vctx;
    PQV_KEM_CTX *dst;

    if (src == NULL) {
        return NULL;
    }
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        return NULL;
    }
    *dst = *src;
    return dst;
}

static int pqv_sig_set_key(PQV_SIG_CTX *ctx, PQV_KEYDATA *key)
{
    if (ctx == NULL || key == NULL || key->alg != &pqv_cross_rsdp_128_small) {
        return 0;
    }
    ctx->key = key;
    return 1;
}

static void pqv_sig_reset(PQV_SIG_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    OPENSSL_clear_free(ctx->msg, ctx->msg_cap);
    ctx->msg = NULL;
    ctx->msg_len = 0;
    ctx->msg_cap = 0;
}

static int pqv_sig_append(PQV_SIG_CTX *ctx, const unsigned char *data, size_t datalen)
{
    unsigned char *next;
    size_t needed;
    size_t cap;

    if (ctx == NULL || (datalen != 0 && data == NULL)) {
        return 0;
    }
    if (datalen == 0) {
        return 1;
    }

    needed = ctx->msg_len + datalen;
    if (needed > ctx->msg_cap) {
        cap = (ctx->msg_cap == 0) ? 256 : ctx->msg_cap;
        while (cap < needed) {
            cap *= 2;
        }
        next = OPENSSL_realloc(ctx->msg, cap);
        if (next == NULL) {
            return 0;
        }
        ctx->msg = next;
        ctx->msg_cap = cap;
    }

    memcpy(ctx->msg + ctx->msg_len, data, datalen);
    ctx->msg_len += datalen;
    return 1;
}

static int pqv_sig_make_signature(PQV_SIG_CTX *ctx,
                                  unsigned char *sig, size_t *siglen,
                                  size_t sigsize,
                                  const unsigned char *msg, size_t msglen)
{
    size_t produced = 0;

    if (ctx == NULL || ctx->key == NULL || siglen == NULL) {
        return 0;
    }

    *siglen = pqv_cross_rsdp_128_small.max_output_len;
    if (sig == NULL) {
        return 1;
    }
    if (sigsize < *siglen) {
        return 0;
    }
    if (pqv_cross_rsdp_128_small.sign(sig, &produced, msg, msglen, ctx->key->priv) != 0) {
        return 0;
    }
    *siglen = produced;
    return 1;
}

static int pqv_sig_check_signature(PQV_SIG_CTX *ctx,
                                   const unsigned char *sig, size_t siglen,
                                   const unsigned char *msg, size_t msglen)
{
    if (ctx == NULL || ctx->key == NULL || sig == NULL) {
        return 0;
    }
    return pqv_cross_rsdp_128_small.verify(sig, siglen, msg, msglen, ctx->key->pub) == 0;
}

static void *pqv_sig_newctx(void *provctx, const char *propq)
{
    PQV_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)propq;

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }
    return ctx;
}

static int pqv_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQV_SIG_CTX *ctx = (PQV_SIG_CTX *)vctx;
    PQV_KEYDATA *key = (PQV_KEYDATA *)vkey;

    (void)params;

    pqv_sig_reset(ctx);
    if (ctx == NULL || key == NULL || !key->has_priv) {
        return 0;
    }
    return pqv_sig_set_key(ctx, key);
}

static int pqv_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                        size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    return pqv_sig_make_signature((PQV_SIG_CTX *)vctx, sig, siglen, sigsize, tbs, tbslen);
}

static int pqv_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQV_SIG_CTX *ctx = (PQV_SIG_CTX *)vctx;
    PQV_KEYDATA *key = (PQV_KEYDATA *)vkey;

    (void)params;

    pqv_sig_reset(ctx);
    if (ctx == NULL || key == NULL || !key->has_pub) {
        return 0;
    }
    return pqv_sig_set_key(ctx, key);
}

static int pqv_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    return pqv_sig_check_signature((PQV_SIG_CTX *)vctx, sig, siglen, tbs, tbslen);
}

static int pqv_sig_digest_sign_init(void *vctx, const char *mdname,
                                    void *vkey, const OSSL_PARAM params[])
{
    (void)mdname;
    return pqv_sig_sign_init(vctx, vkey, params);
}

static int pqv_sig_digest_sign_update(void *vctx, const unsigned char *data, size_t datalen)
{
    return pqv_sig_append((PQV_SIG_CTX *)vctx, data, datalen);
}

static int pqv_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                     size_t *siglen, size_t sigsize)
{
    PQV_SIG_CTX *ctx = (PQV_SIG_CTX *)vctx;

    return pqv_sig_make_signature(ctx, sig, siglen, sigsize, ctx->msg, ctx->msg_len);
}

static int pqv_sig_digest_sign(void *vctx, unsigned char *sigret, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    return pqv_sig_make_signature((PQV_SIG_CTX *)vctx, sigret, siglen, sigsize, tbs, tbslen);
}

static int pqv_sig_digest_verify_init(void *vctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    (void)mdname;
    return pqv_sig_verify_init(vctx, vkey, params);
}

static int pqv_sig_digest_verify_update(void *vctx, const unsigned char *data, size_t datalen)
{
    return pqv_sig_append((PQV_SIG_CTX *)vctx, data, datalen);
}

static int pqv_sig_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    PQV_SIG_CTX *ctx = (PQV_SIG_CTX *)vctx;

    return pqv_sig_check_signature(ctx, sig, siglen, ctx->msg, ctx->msg_len);
}

static int pqv_sig_digest_verify(void *vctx, const unsigned char *sig, size_t siglen,
                                 const unsigned char *tbs, size_t tbslen)
{
    return pqv_sig_check_signature((PQV_SIG_CTX *)vctx, sig, siglen, tbs, tbslen);
}

static void pqv_sig_freectx(void *vctx)
{
    PQV_SIG_CTX *ctx = (PQV_SIG_CTX *)vctx;

    if (ctx == NULL) {
        return;
    }
    pqv_sig_reset(ctx);
    OPENSSL_free(ctx);
}

static void *pqv_sig_dupctx(void *vctx)
{
    PQV_SIG_CTX *src = (PQV_SIG_CTX *)vctx;
    PQV_SIG_CTX *dst;

    if (src == NULL) {
        return NULL;
    }

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        return NULL;
    }
    *dst = *src;
    dst->msg = NULL;
    dst->msg_len = 0;
    dst->msg_cap = 0;
    if (!pqv_sig_append(dst, src->msg, src->msg_len)) {
        pqv_sig_freectx(dst);
        return NULL;
    }
    return dst;
}

static const OSSL_DISPATCH pqv_sntrup761_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pqv_sntrup761_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pqv_key_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pqv_sntrup761_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))pqv_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))pqv_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pqv_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))pqv_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pqv_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pqv_key_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))pqv_sntrup761_query_operation_name },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pqv_key_has },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))pqv_key_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pqv_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pqv_key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pqv_key_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pqv_key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pqv_key_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))pqv_key_dup },
    { 0, NULL }
};

static const OSSL_DISPATCH pqv_cross_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pqv_cross_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pqv_key_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pqv_cross_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))pqv_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))pqv_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pqv_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))pqv_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pqv_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pqv_key_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))pqv_cross_query_operation_name },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pqv_key_has },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))pqv_key_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pqv_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pqv_key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pqv_key_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pqv_key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pqv_key_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))pqv_key_dup },
    { 0, NULL }
};

static const OSSL_DISPATCH pqv_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))pqv_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))pqv_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))pqv_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))pqv_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))pqv_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))pqv_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))pqv_kem_dupctx },
    { 0, NULL }
};

static const OSSL_DISPATCH pqv_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))pqv_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))pqv_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))pqv_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))pqv_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))pqv_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))pqv_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))pqv_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))pqv_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))pqv_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))pqv_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))pqv_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))pqv_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))pqv_sig_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))pqv_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))pqv_sig_dupctx },
    { 0, NULL }
};

static const OSSL_ALGORITHM pqv_keymgmt[] = {
    { PQCLEAN_SNTRUP761_CLEAN_CRYPTO_ALGNAME, PQV_PROPERTIES, pqv_sntrup761_keymgmt_functions,
      "sntrup761 keymgmt" },
    { PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_ALGNAME, PQV_PROPERTIES, pqv_cross_keymgmt_functions,
      "cross-rsdp-128-small keymgmt" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqv_kems[] = {
    { PQCLEAN_SNTRUP761_CLEAN_CRYPTO_ALGNAME, PQV_PROPERTIES, pqv_kem_functions, "sntrup761 kem" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqv_signatures[] = {
    { PQCLEAN_CROSSRSDP128SMALL_CLEAN_CRYPTO_ALGNAME, PQV_PROPERTIES, pqv_signature_functions,
      "cross-rsdp-128-small signature" },
    { NULL, NULL, NULL, NULL }
};

static void pqv_provider_teardown(void *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_PARAM *pqv_provider_gettable_params(void *provctx)
{
    (void)provctx;
    return pqv_provider_gettable_params_def;
}

static int pqv_provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL &&
        !OSSL_PARAM_set_utf8_ptr(p, PQV_PROVIDER_NAME)) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL &&
        !OSSL_PARAM_set_utf8_ptr(p, "0.1")) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL &&
        !OSSL_PARAM_set_utf8_ptr(p, "sntrup761 + cross-rsdp-128-small")) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL &&
        !OSSL_PARAM_set_uint(p, 1)) {
        return 0;
    }
    return 1;
}

static const OSSL_ALGORITHM *pqv_provider_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;

    if (no_cache != NULL) {
        *no_cache = 0;
    }

    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return pqv_keymgmt;
    case OSSL_OP_KEM:
        return pqv_kems;
    case OSSL_OP_SIGNATURE:
        return pqv_signatures;
    default:
        return NULL;
    }
}

static const OSSL_DISPATCH pqv_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))pqv_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))pqv_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))pqv_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pqv_provider_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    PQV_PROVIDER_CTX *ctx;

    (void)in;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return 0;
    }

    ctx->handle = handle;
    *provctx = ctx;
    *out = pqv_provider_functions;
    return 1;
}
