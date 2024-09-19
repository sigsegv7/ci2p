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

#include <sys/stat.h>
#include <sys/queue.h>
#include <peer/reseed.h>
#include <peer/netdb.h>
#include <crypto/i2pcert.h>
#include <lib/file.h>
#include <lib/log.h>
#include <lib/bswap.h>
#include <curl/curl.h>
#include <ctype.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <zip.h>

#define RESEED_SUFFIX "i2pseeds.su3"
#define DEFAULT_SU3_PATH "/etc/ci2p/reseed.su3"
#define DEFAULT_CERTDIR_PATH "/etc/ci2p/certs/"
#define DEFAULT_VARDIR_PATH  "/var/run/ci2p/"
#define DEFAULT_NETDB_PATH DEFAULT_VARDIR_PATH "netdb/"

/*
 * A list of hardcoded URLs to reseed servers
 * used to bootstrap CI2P.
 */
static const char *reseed_urls[] = {
    "https://reseed2.i2p.net/" RESEED_SUFFIX,
    "https://reseed.diva.exchange/" RESEED_SUFFIX,
    "https://reseed-fr.i2pd.xyz/" RESEED_SUFFIX,
    "https://reseed.memcpy.io/" RESEED_SUFFIX,
    "https://reseed.onion.im/" RESEED_SUFFIX,
    "https://i2pseed.creativecowpat.net:8443/" RESEED_SUFFIX,
    "https://reseed.i2pgit.org/" RESEED_SUFFIX,
    "https://banana.incognet.io/" RESEED_SUFFIX,
    "https://reseed-pl.i2pd.xyz/" RESEED_SUFFIX,
    "https://www2.mk16.de/" RESEED_SUFFIX,
    "https://i2p.ghativega.in/" RESEED_SUFFIX,
    "https://i2p.novg.net/" RESEED_SUFFIX,
    "https://reseed.stormycloud.org/" RESEED_SUFFIX
};

/*
 * SU3 signature types, mapped to the
 * su3_hdr.sig_type field.
 */
static const char *su3_sigtypes[] = {
    [0x0000] =   "DSA-SHA1",
    [0x0001] =   "ECDSA-SHA256-P256",
    [0x0002] =   "ECDSA-SHA384-P384",
    [0x0003] =   "ECDSA-SHA512-P521",
    [0x0004] =   "RSA-SHA256-2048",
    [0x0005] =   "RSA-SHA384-3072",
    [0x0006] =   "RSA-SHA512-4096",
    [0x0008] =   "EdDSA-SHA512-Ed25519ph"
};

/* Used for libcurl calls */
static size_t
write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    FILE *fp = (FILE *)userp;
    size_t written = fwrite(contents, size, nmemb, fp);

    return written;
}

/*
 * Returns pointer to cert if cert matches the signer
 * ID, otherwise NULL is returned.
 */
static struct i2pcert *
cert_match(const char *signer_id, char *cert_path)
{
    struct i2pcert *c;

    if (load_cert(cert_path, &c) != 0) {
        return NULL;
    }

    if (strstr(c->issuer, signer_id) == NULL) {
        free_cert(c);
        return NULL;
    }

    return c;
}

/*
 * Locate a cert from an I2p signer ID
 */
static struct i2pcert *
get_cert(const char *signer_id)
{
    size_t pathlen;
    char *pathbuf;
    struct i2pcert *cert;
    struct dirent *dir;
    DIR *d;

    d = opendir(DEFAULT_CERTDIR_PATH);
    if (d == NULL) {
        return NULL;
    }

    while ((dir = readdir(d)) != NULL) {
        if (*dir->d_name == '.') {
            continue;
        }

        pathlen = strlen(DEFAULT_CERTDIR_PATH) + strlen(dir->d_name);
        pathbuf = malloc(pathlen + 1);

        /* Construct the path */
        strcpy(pathbuf, DEFAULT_CERTDIR_PATH);
        strcat(pathbuf, dir->d_name);
        pathbuf[pathlen] = '\0';

        cert = cert_match(signer_id, pathbuf);
        free(pathbuf);

        if (cert != NULL) {
            return cert;
        }
    }

    closedir(d);
    return NULL;
}

static int
get_su3(CURL *curl, const char *url)
{
    int res, status;
    FILE *fp;

    fp = fopen(DEFAULT_SU3_PATH, "wb");
    if (fp == NULL) {
        printf(LOG_WARN "Failed to open %s\n", DEFAULT_SU3_PATH);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    fclose(fp);

    if (status != 200 || res == CURLE_ABORTED_BY_CALLBACK) {
        return -1;
    }

    return 0;
}

static int
netdb_get_key(const char *dat, const char *key, char *res)
{
    size_t index = 0;
    char *value, *p, *p1;
    int assign_start = 0;

    value = strstr(dat, key);
    if (value == NULL) {
        return -1;
    }

    for (p = value; *p != '\0'; ++p) {
        if (assign_start == 0 && *p != '=') {
            continue;
        } else if (*p == '=' && assign_start == 0) {
            assign_start = 1;
            ++p;
        }

        while (iscntrl(*p) && *p != '\0') {
            ++p;
        }

        for (p1 = p; *p1 != ';' && *p1 != '\0'; ++p1) {
            if (*p1 == ' ') {
                continue;
            }

            if (!isascii(*p1) || iscntrl(*p1)) {
                res[0] = '\0';
                return -1;
            }

            res[index++] = *p1;
            res[index] = '\0';
        }

        break;
    }

    return 0;
}

/*
 * Verify the SU3 signature.
 *
 * @hdr: .su3 header
 * @cert: Certificate
 *
 * TODO: Validate .su3 signature
 *
 */
static int
verify_su3(const struct su3_hdr *hdr, struct i2pcert *cert)
{
    BIO *bio;

    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (bio == NULL) {
        return -1;
    }

    printf("** Begin dump of public key parameters **\n");
    EVP_PKEY_print_public(bio, cert->pubkey, 0, NULL);
    BIO_free(bio);
    return 0;
}

static void
rinfchain_free(struct rinfchain *rinfchain)
{
    struct router_info *tmp;

    while ((tmp = TAILQ_FIRST(&rinfchain->head)) != NULL) {
        TAILQ_REMOVE(&rinfchain->head, tmp, link);
        free(tmp->address);
        free(tmp->port);
        free(tmp);
    }

    free(rinfchain);
}

/*
 * Unpack an .su3 payload and give back a router info
 * chain (rinfchain) through 'res'.
 *
 * @reseed_payload: Payload to unpack.
 * @size: Size of payload.
 * @res: Output for router info chain.
 */
static int
unpack_payload(const char *reseed_payload, size_t size,
    struct rinfchain **res)
{
    const size_t BLOCKSIZE = 128;
    int error, zip_entries;
    size_t bytes_read;
    double count, progress = 0;
    double max_progress;
    char tmp_path[512];
    char netdb_path[1024];
    char *buf;
    char ip[64], port[32];
    struct file *fp, *netdb_fp;
    struct zip_file *zfp;
    struct zip_stat stat;
    struct zip *za;
    struct rinfchain *rc;
    struct router_info *rinf;

    memset(ip, 0, sizeof(ip));
    memset(port, 0, sizeof(port));

    snprintf(tmp_path, sizeof(tmp_path), "%sci2p-peers.zip",
        DEFAULT_VARDIR_PATH);

    /*
     * Open [DEFAULT_VARDIR_PATH]/ci2p-%d-peers.zip so we can
     * write the zip there and open it with libzip.
     */
    if ((error = open_file(tmp_path, "w", &fp)) < 0) {
        printf(LOG_ERR "Failed to create \"%s\"", tmp_path);
        return error;
    }

    /* Write the zip */
    fwrite(reseed_payload, sizeof(char), size, FHANDLE(fp));
    close_file(fp);

    za = zip_open(tmp_path, ZIP_RDONLY, NULL);
    if (za == NULL) {
        printf(LOG_ERR "Failed to open \"%s\"", tmp_path);
        return -1;
    }

    zip_entries = zip_get_num_entries(za, 0);
    rc = malloc(sizeof(*rc));
    TAILQ_INIT(&rc->head);

    printf(LOG_INFO "Reading payload...\n");
    printf(LOG_INFO "Populating netdb with ~%d entries...\n", zip_entries);

    for (size_t i = 0; i < zip_entries; ++i) {
        if (zip_stat_index(za, i, 0, &stat) != 0) {
            printf(LOG_WARN "Skipping entry %d\n", i);
            continue;
        }

        zfp = zip_fopen_index(za, i, 0);
        if (zfp == NULL) {
            printf(LOG_WARN "Skipping entry %d\n", i);
            continue;
        }

        /* Get netdb path */
        snprintf(netdb_path, sizeof(tmp_path), "%s%s",
            DEFAULT_NETDB_PATH, stat.name);

        if (open_file(netdb_path, "w", &netdb_fp) < 0) {
            printf(LOG_WARN "Skipping entry %d\n", i);
            close_file(netdb_fp);
            break;
        }

        buf = calloc(stat.size + 1, sizeof(char));
        bytes_read = 0;
        max_progress = stat.size;

        while (bytes_read != stat.size) {
            count = zip_fread(zfp, buf, BLOCKSIZE);
            if (count < 0) {
                printf(LOG_WARN "Skipping entry %d\n", i);
                break;
            }

            netdb_get_key(buf, "host", ip);
            netdb_get_key(buf, "port", port);

            if (ip[0] != '\0' && port[0] != '\0') {
                rinf = calloc(1, sizeof(*rinf));
                rinf->address = strdup(ip);
                rinf->port = strdup(port);
                TAILQ_INSERT_TAIL(&rc->head, rinf, link);
            }

            progress = (bytes_read / max_progress) * 100;
            log_diag(LOG_INFO "Unpacking entry %d (%.1f%%)\n", i, progress);

            fwrite(buf, sizeof(char), BLOCKSIZE, FHANDLE(netdb_fp));
            bytes_read += count;
            ip[0] = '\0';
            port[0] = '\0';
        }

        log_diag("... OK\n");
        close_file(netdb_fp);
        zip_fclose(zfp);
        free(buf);
    }

    *res = rc;
    zip_close(za);
    return 0;
}

int
su3_reseed(const char *file)
{
    int error = 0;
    uint8_t signer_idlen;
    uint8_t version_len;
    uint16_t sig_len, sig_type;
    uint64_t content_len;
    off_t sig_off, payload_off;
    char *sig_buf, *id_buf;
    char *payload;
    const char *sig_typestr;
    struct file *fp;
    struct su3_hdr hdr;
    struct i2pcert *cert;
    struct router_info *tmp;
    struct rinfchain *rc;

    error = open_file(file, "r", &fp);
    if (error < 0) {
        return error;
    }

    /* Read header and verify magic */
    fread(&hdr, sizeof(char), sizeof(hdr), FHANDLE(fp));
    if (memcmp(hdr.magic, SU3_MAGIC, SU3_MAGLEN) != 0) {
        log_diag(LOG_WARN "Failed to verify header magic\n");
        close_file(fp);
        return -1;
    }

    /* Extract length fields */
    sig_len = bswap16(hdr.sig_len);
    sig_type = bswap16(hdr.sig_type);
    content_len = bswap64(hdr.content_len);
    signer_idlen = hdr.signer_idlen;
    version_len = hdr.version_len;

    /* Try to allocate the signature buffer */
    sig_buf = calloc(sig_len + 1, sizeof(char));
    if (sig_buf == NULL) {
        error = -ENOMEM;
        goto done;
    }

    /* Try to allocate the signer ID buffer */
    id_buf = calloc(signer_idlen + 1, sizeof(char));
    if (id_buf == NULL) {
        error = -ENOMEM;
        goto done;
    }

    /* Try to allocate the payload buffer */
    payload = calloc(content_len + 1, sizeof(char));
    if (payload == NULL) {
        return -ENOMEM;
        goto done;
    }

    /* Read the signature */
    sig_off = sizeof(hdr) + signer_idlen + content_len + version_len;
    fseek(FHANDLE(fp), sig_off, SEEK_SET);
    fread(sig_buf, sizeof(char), sig_len, FHANDLE(fp));

    /* Read the signer ID */
    fseek(FHANDLE(fp), sizeof(hdr) + version_len, SEEK_SET);
    fread(id_buf, sizeof(char), signer_idlen, FHANDLE(fp));

    /* Read in the payload */
    payload_off = sizeof(hdr) + signer_idlen + version_len;
    fseek(FHANDLE(fp), payload_off, SEEK_SET);
    fread(payload, sizeof(char), content_len, FHANDLE(fp));

    printf(LOG_INFO "Fetching cert from signer ID: %s\n", id_buf);
    if ((cert = get_cert(id_buf)) == NULL) {
        log_diag(LOG_WARN "Failed to find matching cert\n");
        error = -1;
        goto done;
    }

    /* Show what cert dates are valid */
    log_diag(LOG_INFO "Valid not before %s - not after %s\n",
        cert->not_before, cert->not_after);

    sig_typestr = su3_sigtypes[sig_type];
    printf(LOG_INFO "Signature type: %s\n", sig_typestr);

    error = verify_su3(&hdr, cert);
    if (error != 0) {
        printf(LOG_WARN "Bad signature, cert, or public key - rejecting...\n");
        goto done;
    }

    /* Now... Populate the netdb */
    error = unpack_payload(payload, content_len, &rc);
    if (error != 0) {
        printf(LOG_WARN "Failed to unpack payload\n");
        goto done;
    }

    printf(LOG_INFO "Reading routerinfo chain...\n");
    TAILQ_FOREACH(tmp, &rc->head, link) {
        printf(LOG_INFO "Found node @ %s:%s\n",
            tmp->address, tmp->port);
    }

    rinfchain_free(rc);
    rc = NULL;
done:
    free_cert(cert);
    free(id_buf);
    close_file(fp);
    return error;
}

int
request_reseed(void)
{
    size_t url_count;
    CURL *curl = curl_easy_init();

    if (curl == NULL) {
        return -1;
    }

    url_count = sizeof(reseed_urls) / sizeof(reseed_urls[0]);
    for (size_t i = 0; i < url_count; ++i) {
        log_diag(LOG_INFO "[bootstrap] Trying %s...\n", reseed_urls[i]);
        get_su3(curl, reseed_urls[i]);

        if (su3_reseed(DEFAULT_SU3_PATH) == 0) {
            break;
        }
    }

    curl_easy_cleanup(curl);
    return 0;
}
