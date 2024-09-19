/*
 * Copyright (c) 2023-2024 Ian Marco Moffett and the Osmora Team.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Hyra nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <crypto/i2pcert.h>
#include <lib/file.h>
#include <lib/log.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

/*
 * Convert ASN1_TIME to an ISO8601 timestamp
 *
 * @t: ASN1 time object.
 * @buf: Buffer to store new timestamp.
 * @len: Length of buffer.
 */
static int
to_iso8601(ASN1_TIME *t, char *buf, size_t len)
{
    int retval;
    BIO *b;

    b = BIO_new(BIO_s_mem());
    retval = ASN1_TIME_print(b, t);

    if (retval <= 0) {
        return -1;
    }

    retval = BIO_gets(b, buf, len);

    if (retval <= 0) {
        return -1;
    }

    BIO_free(b);
    return 0;
}

/*
 * Release the memory for a cert object.
 *
 * @cert: Cert to deallocate.
 */
void
free_cert(struct i2pcert *cert)
{
    if (cert->issuer != NULL)
        free(cert->issuer);
    if (cert->pubkey != NULL)
        EVP_PKEY_free(cert->pubkey);

    free(cert);
}

/*
 * Create a new cert object from a file.
 *
 * @filename: X.509 cert file
 * @res: Pointer to resulting cert object.
 */
int
load_cert(const char *filename, struct i2pcert **res)
{
    struct file *fp;
    struct i2pcert *cert;
    size_t len;
    char *issuer;
    char pubkey[1024];
    int retval = 0;
    int pubkey_algonid;
    X509 *x509 = NULL;
    ASN1_TIME *not_before = NULL;
    ASN1_TIME *not_after = NULL;

    if (res == NULL) {
        return -EINVAL;
    }

    retval = open_file(filename, "r", &fp);
    if (retval < 0) {
        return retval;
    }

    cert = malloc(sizeof(*cert));
    if (cert == NULL) {
        retval = errno;
        goto done;
    }

    /* Read the X.509 cert */
    x509 = PEM_read_X509(FHANDLE(fp), NULL, NULL, NULL);
    if (x509 == NULL) {
        retval = -1;
        goto done;
    }

    /* Fetch cert issuer */
    issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);
    cert->issuer = strdup(issuer);

    /* Release memory for issuer string */
    OPENSSL_free(issuer);
    issuer = NULL;

    /* Get the public key */
    cert->pubkey = X509_get0_pubkey(x509);
    if (cert->pubkey == NULL) {
        free_cert(cert);
        retval = -1;
        goto done;
    }

    /* Get cert validity period */
    not_before = X509_get_notBefore(x509);
    not_after = X509_get_notAfter(x509);

    retval = to_iso8601(not_before, cert->not_before, sizeof(cert->not_before));
    if (retval != 0) {
        free_cert(cert);
        goto done;
    }

    retval = to_iso8601(not_after, cert->not_after, sizeof(cert->not_after));
    if (retval != 0) {
        free_cert(cert);
        goto done;
    }

    *res = cert;
done:
    if (not_before != NULL)
        ASN1_TIME_free(not_before);
    if (not_after != NULL)
        ASN1_TIME_free(not_after);

    close_file(fp);
    return retval;
}
