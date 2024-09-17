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

#ifndef PEER_RESEED_H_
#define PEER_RESEED_H_

#include <stdint.h>

/* File type values */
#define SU3_FILE_ZIP    0x00
#define SU3_FILE_XML    0x01
#define SU3_FILE_HTML   0x02
#define SU3_FILE_XMLGZ  0x03
#define SU3_FILE_TXTGZ  0x04
#define SU3_FILE_DMG    0x05
#define SU3_FILE_EXE    0x06

/* Reseed content type value */
#define SU3_CONTENT_RESEED 0x03

struct su3_hdr {
    char magic[6];          /* Magic number (I2Psu3) */
    uint8_t unused;         /* Unused */
    uint8_t version;        /* SU3 file format version */
    uint16_t sig_type;      /* Signature type */
    uint16_t sig_len;       /* Signature length */
    uint8_t unused1;        /* Unused */
    uint8_t version_len;    /* Version length in bytes (w/ pad) */
    uint8_t unused2;        /* Unused */
    uint8_t signer_idlen;   /* Signer ID length in bytes */
    uint64_t content_len;   /* Content length (not including hdr or sig) */
    uint8_t unused3;        /* Unused */
    uint8_t file_type;      /* File type */
    uint8_t unused4;        /* Unused */
    uint8_t content_type;   /* Content type */
    char unused5[12];       /* Unused */
    char data[];
} __attribute__((packed));

#endif  /* PEER_RESEED_H_ */
