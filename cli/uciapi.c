#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uci/sdf.h"

#define DEFAULT_OPERATION "kem-demo"
#define DEFAULT_PROVIDER "pqvariantprovider"
#define DEFAULT_ALGORITHM "sntrup761"
#define DEFAULT_ALGID ((ULONG)0x00F3E761u)
#define DEFAULT_PIN "12345678"

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--enable-log] [--log-file path] --operation kem-demo [--provider name] [--algorithm name] [--algid 0xHEX] [--pin value]\n",
            argv0);
}

static ULONG parse_algid(const char *text)
{
    unsigned long value;
    char *end = NULL;

    errno = 0;
    value = strtoul(text, &end, 0);
    if (errno != 0 || end == text || (end != NULL && *end != '\0') || value > 0xFFFFFFFFul) {
        return 0;
    }
    return (ULONG)value;
}

static void print_hex(const char *label, const BYTE *buf, ULONG len)
{
    ULONG i;

    printf("%s=", label);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *operation = DEFAULT_OPERATION;
    const char *provider = DEFAULT_PROVIDER;
    const char *algorithm = DEFAULT_ALGORITHM;
    const char *pin = DEFAULT_PIN;
    const char *log_file = NULL;
    ULONG algid = DEFAULT_ALGID;
    int enable_log = 0;
    HANDLE dev = NULL;
    HANDLE sess = NULL;
    HANDLE prov = NULL;
    HANDLE key = NULL;
    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;
    BYTE *ss1 = NULL;
    BYTE *ss2 = NULL;
    BYTE *ct = NULL;
    ULONG ss1_len = 0;
    ULONG ss2_len = 0;
    ULONG ct_len = 0;
    LONG rc;
    char props[256];
    int i;
    int exit_code = 2;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--operation") == 0 && i + 1 < argc) {
            operation = argv[++i];
        } else if (strcmp(argv[i], "--enable-log") == 0) {
            enable_log = 1;
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            log_file = argv[++i];
            enable_log = 1;
        } else if (strcmp(argv[i], "--provider") == 0 && i + 1 < argc) {
            provider = argv[++i];
        } else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            algorithm = argv[++i];
        } else if (strcmp(argv[i], "--algid") == 0 && i + 1 < argc) {
            algid = parse_algid(argv[++i]);
            if (algid == 0) {
                fprintf(stderr, "[FAIL] invalid --algid\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--pin") == 0 && i + 1 < argc) {
            pin = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (strcmp(operation, "kem-demo") != 0) {
        fprintf(stderr, "[FAIL] unsupported --operation=%s\n", operation);
        return 2;
    }

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props)) {
        fprintf(stderr, "[FAIL] provider name too long\n");
        return 2;
    }

    UCI_SDF_SetLogEnabled(enable_log);
    if (log_file != NULL && !UCI_SDF_SetLogFile(log_file)) {
        fprintf(stderr, "[FAIL] cannot open log file: %s\n", log_file);
        return 2;
    }

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_OpenDevice rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_OpenSession rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    rc = SDF_GetPrivateKeyAccessRight(sess, 1, (LPSTR)pin, (ULONG)strlen(pin));
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_GetPrivateKeyAccessRight rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    rc = SDFU_LoadProvider(sess, (const CHAR *)provider, &prov);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[FAIL] SDFU_LoadProvider(%s) rc=0x%08X (check OPENSSL_MODULES)\n",
                provider, (unsigned int)rc);
        goto cleanup;
    }

    rc = SDFR_RegisterAlgName(algid, (const CHAR *)algorithm, (const CHAR *)props);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDFR_RegisterAlgName rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)algorithm, (const CHAR *)props, &key);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDFU_GenerateKeyPair rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = algid;
    req.hKeyHandle = key;
    rsp.puiOutputLength = &ss1_len;
    rsp.puiExtraOutputLength = &ct_len;

    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK || ss1_len == 0 || ct_len == 0) {
        fprintf(stderr, "[FAIL] SDFR_Execute KEM_ENCAPSULATE(size) rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    ss1 = (BYTE *)malloc(ss1_len);
    ss2 = (BYTE *)malloc(ss1_len);
    ct = (BYTE *)malloc(ct_len);
    if (ss1 == NULL || ss2 == NULL || ct == NULL) {
        fprintf(stderr, "[FAIL] malloc failed\n");
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = algid;
    req.hKeyHandle = key;
    rsp.pucOutput = ss1;
    rsp.puiOutputLength = &ss1_len;
    rsp.pucExtraOutput = ct;
    rsp.puiExtraOutputLength = &ct_len;

    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDFR_Execute KEM_ENCAPSULATE rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    ss2_len = ss1_len;
    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_DECAPSULATE;
    req.uiAlgID = algid;
    req.hKeyHandle = key;
    req.pucExtraInput = ct;
    req.uiExtraInputLength = ct_len;
    rsp.pucOutput = ss2;
    rsp.puiOutputLength = &ss2_len;

    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDFR_Execute KEM_DECAPSULATE rc=0x%08X\n", (unsigned int)rc);
        goto cleanup;
    }

    print_hex("ciphertext", ct, ct_len);
    print_hex("shared_secret_enc", ss1, ss1_len);
    print_hex("shared_secret_dec", ss2, ss2_len);
    printf("shared-secret-match=%s\n",
           (ss1_len == ss2_len && memcmp(ss1, ss2, ss1_len) == 0) ? "yes" : "no");

    if (ss1_len != ss2_len || memcmp(ss1, ss2, ss1_len) != 0) {
        fprintf(stderr, "[FAIL] shared secret mismatch\n");
        goto cleanup;
    }

    exit_code = 0;

cleanup:
    if (key != NULL)
        (void)SDF_DestroyKey(sess, key);
    if (prov != NULL)
        (void)SDFU_UnloadProvider(prov);
    if (sess != NULL)
        (void)SDF_CloseSession(sess);
    if (dev != NULL)
        (void)SDF_CloseDevice(dev);
    free(ss1);
    free(ss2);
    free(ct);
    return exit_code;
}
