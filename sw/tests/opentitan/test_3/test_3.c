// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/dif/dif_hmac.h"

#include "hmac_regs.h"
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"


// ---------------------------------------------------------------------------
// Tipi dati 
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t  *data;
    uint32_t  n;
} titanssl_batch_t;

typedef struct __attribute__((packed)) {
    titanssl_batch_t *src;
    titanssl_batch_t *dst;
    uint32_t          n_src;
    uint32_t          n_dst;
} titanssl_mbox_t;


// ---------------------------------------------------------------------------
// Test Parameters
// ---------------------------------------------------------------------------
#define TITANSSL_TEST_SRC_SIZE  65536  
#define TITANSSL_TEST_DST_SIZE  32
#define TITANSSL_PAGE_SIZE      4096


#define TITANSSL_BATCH_SRC_BASE  0xe0001000UL
#define TITANSSL_BATCH_DST_BASE  0xe0001100UL
#define TITANSSL_DATA_SRC_BASE   0xe0002000UL 
#define TITANSSL_DATA_DST_BASE   0xe0003000UL

static const dif_hmac_digest_t kExpectedShaDigest = {
    .digest = {
        0x9ca9cc31, 0x731c23ae, 0x4f489eac, 0x9f3df0de,
        0x7505dc0b, 0x7747c2b9, 0x64a0af79, 0xde2f2560
    },
};


// ---------------------------------------------------------------------------
// Config HMAC 
// ---------------------------------------------------------------------------
static const dif_hmac_transaction_t kHmacTransactionConfig = {
    .digest_endianness  = kDifHmacEndiannessLittle,
    .message_endianness = kDifHmacEndiannessLittle,
};


// ---------------------------------------------------------------------------
// Mailbox: istanza locale in SRAM interna
// ---------------------------------------------------------------------------
static titanssl_mbox_t titanssl_mbox_storage;
static titanssl_mbox_t * const titanssl_mbox = &titanssl_mbox_storage;

// Registro pass/fail leggibile dal testbench via memory probe.
volatile uint32_t test_result = 0x00000000;


// ---------------------------------------------------------------------------
// initialize_memory
// ---------------------------------------------------------------------------
static void initialize_memory(void)
{
    titanssl_mbox->src   = (titanssl_batch_t *)TITANSSL_BATCH_SRC_BASE;
    titanssl_mbox->dst   = (titanssl_batch_t *)TITANSSL_BATCH_DST_BASE;
    titanssl_mbox->n_src = 1 + (TITANSSL_TEST_SRC_SIZE - 1) / TITANSSL_PAGE_SIZE;
    titanssl_mbox->n_dst = 1 + (TITANSSL_TEST_DST_SIZE  - 1) / TITANSSL_PAGE_SIZE;

    // Azzera l'unico buffer sorgente
    // Tutti i descriptor src puntano a questo stesso buffer.
    volatile uint8_t *pb = (volatile uint8_t *)TITANSSL_DATA_SRC_BASE;
    for (size_t j = 0; j < TITANSSL_PAGE_SIZE; j++) {
        pb[j] = 0;
    }

    // Inizializza i 16 descriptor src: tutti puntano al medesimo buffer.
    titanssl_batch_t *src = (titanssl_batch_t *)TITANSSL_BATCH_SRC_BASE;
    for (size_t i = 0; i < titanssl_mbox->n_src; i++) {
        src[i].data = (uint8_t *)TITANSSL_DATA_SRC_BASE;  // stesso indirizzo
        src[i].n    = TITANSSL_PAGE_SIZE;
    }

    // Inizializza il descriptor dst e azzera il buffer digest.
    titanssl_batch_t *dst = (titanssl_batch_t *)TITANSSL_BATCH_DST_BASE;
    dst[0].data = (uint8_t *)TITANSSL_DATA_DST_BASE;
    dst[0].n    = TITANSSL_TEST_DST_SIZE;
    volatile uint8_t *pd = (volatile uint8_t *)TITANSSL_DATA_DST_BASE;
    for (size_t j = 0; j < TITANSSL_TEST_DST_SIZE; j++) {
        pd[j] = 0;
    }
}


// ---------------------------------------------------------------------------
// titanssl_sha256
// ---------------------------------------------------------------------------
static void titanssl_sha256(void)
{
    dif_hmac_t   hmac;
    dif_result_t res;

    titanssl_batch_t * const src   = titanssl_mbox->src;
    titanssl_batch_t * const dst   = titanssl_mbox->dst;
    const uint32_t           n_src = titanssl_mbox->n_src;

    res = dif_hmac_init(
        mmio_region_from_addr(TOP_EARLGREY_HMAC_BASE_ADDR),
        &hmac
    );
    res = dif_hmac_mode_sha256_start(&hmac, kHmacTransactionConfig);

    for (size_t i = 0; i < n_src; i++) {
        const uint8_t  *kData     = src[i].data;
        const uint32_t  kDataSize = src[i].n;
        const uint8_t  *dp        = src[i].data;

        while (dp - kData < kDataSize) {
            uint32_t sent_bytes;
            res = dif_hmac_fifo_push(
                &hmac, dp,
                kDataSize - (dp - kData),
                &sent_bytes
            );
            dp += sent_bytes;

            if (res == kDifIpFifoFull) {
                uint32_t fifo_depth;
                do {
                    res = dif_hmac_fifo_count_entries(&hmac, &fifo_depth);
                } while (fifo_depth != 0);
            }
        }
    }

    res = dif_hmac_process(&hmac);
    while (!mmio_region_get_bit32(
        hmac.base_addr,
        HMAC_INTR_STATE_REG_OFFSET,
        HMAC_INTR_STATE_HMAC_DONE_BIT
    ));

    do {
        res = dif_hmac_finish(&hmac, (dif_hmac_digest_t *)(dst->data));
    } while (res != kDifOk);
}


// ---------------------------------------------------------------------------
// check_digest
// ---------------------------------------------------------------------------
static int check_digest(void)
{
    const uint32_t *got      = (const uint32_t *)(titanssl_mbox->dst->data);
    const uint32_t *expected = kExpectedShaDigest.digest;
    uint32_t        ok       = 1;

    for (int i = 0; i < 8; i++) {
        if (got[i] != expected[i]) {
            ok = 0;
            break;
        }
    }

    test_result = ok ? 0x900DD00Du : 0xDEADBEEFu;
    return ok ? 0 : 1;
}


// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void)
{
    initialize_memory();
    titanssl_sha256();
    return check_digest();
}
