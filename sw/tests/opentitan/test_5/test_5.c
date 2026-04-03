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

// loop di sha-256 senza nessun check

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
// Parametri test
// ---------------------------------------------------------------------------
#define TITANSSL_TEST_SRC_SIZE  65536
#define TITANSSL_TEST_DST_SIZE  32
#define TITANSSL_PAGE_SIZE      4096

// Layout SRAM interna (0xe0000000–0xe000ffff):
//   0xe0001000  batch src descriptors (16×8 = 128 byte)
//   0xe0001100  batch dst descriptor  (8 byte)
//   0xe0002000  buffer src            (4096 byte, condiviso da tutti i descriptor)
//   0xe0003000  buffer dst digest     (32 byte)
#define TITANSSL_BATCH_SRC_BASE  0xe0001000UL
#define TITANSSL_BATCH_DST_BASE  0xe0001100UL
#define TITANSSL_DATA_SRC_BASE   0xe0002000UL
#define TITANSSL_DATA_DST_BASE   0xe0003000UL


// ---------------------------------------------------------------------------
// Config HMAC
// ---------------------------------------------------------------------------
static const dif_hmac_transaction_t kHmacTransactionConfig = {
    .digest_endianness  = kDifHmacEndiannessLittle,
    .message_endianness = kDifHmacEndiannessLittle,
};


// ---------------------------------------------------------------------------
// Mailbox in .bss — contenitore per puntatori e contatori del test
// ---------------------------------------------------------------------------
static titanssl_mbox_t titanssl_mbox_storage;
static titanssl_mbox_t * const titanssl_mbox = &titanssl_mbox_storage;


// ---------------------------------------------------------------------------
// initialize_memory
//
// Prepara descriptor e buffer una sola volta prima del loop.
// Tutti i 16 descriptor src puntano allo stesso buffer da 4 KiB:
// l'HMAC processa la stessa pagina 16 volte = 65536 byte di zeri.
// ---------------------------------------------------------------------------
static void initialize_memory(void)
{
    titanssl_mbox->src   = (titanssl_batch_t *)TITANSSL_BATCH_SRC_BASE;
    titanssl_mbox->dst   = (titanssl_batch_t *)TITANSSL_BATCH_DST_BASE;
    titanssl_mbox->n_src = 1 + (TITANSSL_TEST_SRC_SIZE - 1) / TITANSSL_PAGE_SIZE;
    titanssl_mbox->n_dst = 1 + (TITANSSL_TEST_DST_SIZE  - 1) / TITANSSL_PAGE_SIZE;

    // Azzera buffer sorgente — inizializza anche lo scrambling del sram_ctrl
    volatile uint8_t *pb = (volatile uint8_t *)TITANSSL_DATA_SRC_BASE;
    for (size_t j = 0; j < TITANSSL_PAGE_SIZE; j++) pb[j] = 0;

    // Tutti i descriptor src puntano allo stesso buffer
    titanssl_batch_t *src = (titanssl_batch_t *)TITANSSL_BATCH_SRC_BASE;
    for (size_t i = 0; i < titanssl_mbox->n_src; i++) {
        src[i].data = (uint8_t *)TITANSSL_DATA_SRC_BASE;
        src[i].n    = TITANSSL_PAGE_SIZE;
    }

    // Descriptor dst e buffer digest
    titanssl_batch_t *dst = (titanssl_batch_t *)TITANSSL_BATCH_DST_BASE;
    dst[0].data = (uint8_t *)TITANSSL_DATA_DST_BASE;
    dst[0].n    = TITANSSL_TEST_DST_SIZE;
    volatile uint8_t *pd = (volatile uint8_t *)TITANSSL_DATA_DST_BASE;
    for (size_t j = 0; j < TITANSSL_TEST_DST_SIZE; j++) pd[j] = 0;
}


// ---------------------------------------------------------------------------
// titanssl_sha256
//
// Calcola SHA-256 sui dati descritti dalla mailbox tramite l'IP HMAC.
// Spinge i dati nel FIFO hardware a blocchi, aspettando quando pieno.
// ---------------------------------------------------------------------------
static void titanssl_sha256(void)
{
    dif_hmac_t   hmac;
    dif_result_t res;

    titanssl_batch_t * const src   = titanssl_mbox->src;
    titanssl_batch_t * const dst   = titanssl_mbox->dst;
    const uint32_t           n_src = titanssl_mbox->n_src;

    res = dif_hmac_init(
        mmio_region_from_addr(TOP_EARLGREY_HMAC_BASE_ADDR), &hmac);
    res = dif_hmac_mode_sha256_start(&hmac, kHmacTransactionConfig);

    for (size_t i = 0; i < n_src; i++) {
        const uint8_t  *kData     = src[i].data;
        const uint32_t  kDataSize = src[i].n;
        const uint8_t  *dp        = src[i].data;

        while (dp - kData < kDataSize) {
            uint32_t sent_bytes;
            res = dif_hmac_fifo_push(&hmac, dp,
                kDataSize - (dp - kData), &sent_bytes);
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
    while (!mmio_region_get_bit32(hmac.base_addr,
        HMAC_INTR_STATE_REG_OFFSET, HMAC_INTR_STATE_HMAC_DONE_BIT));

    do {
        res = dif_hmac_finish(&hmac, (dif_hmac_digest_t *)(dst->data));
    } while (res != kDifOk);
}


// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void)
{
    initialize_memory();

    while(1) {
        titanssl_sha256();
    }
}
