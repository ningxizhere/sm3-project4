/*
 * File: sm3.c
 * Description: A basic C implementation of the SM3 hash algorithm.
 * This version is complete and includes the special function required
 * for the length-extension attack.
 */
 #include "sm3.h"
 #include <string.h>
 
 // --- Helper Macros and Functions ---
 
 #define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
 
 static void uint32_to_be(uint32_t n, unsigned char *dst) {
     dst[0] = (n >> 24) & 0xFF;
     dst[1] = (n >> 16) & 0xFF;
     dst[2] = (n >> 8) & 0xFF;
     dst[3] = n & 0xFF;
 }
 
 static uint32_t be_to_uint32(const unsigned char *data) {
     return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
            ((uint32_t)data[2] << 8) | data[3];
 }
 
 #define FF_00_15(X, Y, Z) ((X) ^ (Y) ^ (Z))
 #define GG_00_15(X, Y, Z) ((X) ^ (Y) ^ (Z))
 #define FF_16_63(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
 #define GG_16_63(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))
 
 #define P0(X) ((X) ^ ROTL((X), 9) ^ ROTL((X), 17))
 #define P1(X) ((X) ^ ROTL((X), 15) ^ ROTL((X), 23))
 
 static const uint32_t IV[8] = {
     0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
     0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
 };
 
 static uint32_t T(int j) {
     return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
 }
 
 // --- Core Compression Function ---
 
 static void sm3_compress(sm3_ctx_t *ctx) {
     uint32_t W[68], W_prime[64];
     uint32_t A, B, C, D, E, F, G, H;
     uint32_t SS1, SS2, TT1, TT2;
     int j;
 
     for (j = 0; j < 16; j++) W[j] = be_to_uint32(ctx->buffer + j * 4);
     for (j = 16; j < 68; j++) W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
     for (j = 0; j < 64; j++) W_prime[j] = W[j] ^ W[j + 4];
 
     A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];
     E = ctx->state[4]; F = ctx->state[5]; G = ctx->state[6]; H = ctx->state[7];
 
     for (j = 0; j < 64; j++) {
         SS1 = ROTL(ROTL(A, 12) + E + ROTL(T(j), j), 7);
         SS2 = SS1 ^ ROTL(A, 12);
         if (j < 16) {
             TT1 = FF_00_15(A, B, C) + D + SS2 + W_prime[j];
             TT2 = GG_00_15(E, F, G) + H + SS1 + W[j];
         } else {
             TT1 = FF_16_63(A, B, C) + D + SS2 + W_prime[j];
             TT2 = GG_16_63(E, F, G) + H + SS1 + W[j];
         }
         D = C; C = ROTL(B, 9); B = A; A = TT1;
         H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
     }
 
     ctx->state[0] ^= A; ctx->state[1] ^= B; ctx->state[2] ^= C; ctx->state[3] ^= D;
     ctx->state[4] ^= E; ctx->state[5] ^= F; ctx->state[6] ^= G; ctx->state[7] ^= H;
 }
 
 // --- Standard SM3 Interface Functions ---
 
 void sm3_init(sm3_ctx_t *ctx) {
     memcpy(ctx->state, IV, sizeof(IV));
     ctx->total_len = 0;
     ctx->buffer_len = 0;
 }
 
 void sm3_update(sm3_ctx_t *ctx, const unsigned char *data, size_t len) {
     ctx->total_len += len;
     size_t remaining_len = len;
     size_t data_offset = 0;
 
     if (ctx->buffer_len > 0) {
         size_t to_fill = 64 - ctx->buffer_len;
         if (remaining_len < to_fill) {
             memcpy(ctx->buffer + ctx->buffer_len, data, remaining_len);
             ctx->buffer_len += remaining_len;
             return;
         }
         memcpy(ctx->buffer + ctx->buffer_len, data, to_fill);
         sm3_compress(ctx);
         data_offset += to_fill;
         remaining_len -= to_fill;
     }
 
     while (remaining_len >= 64) {
         memcpy(ctx->buffer, data + data_offset, 64);
         sm3_compress(ctx);
         data_offset += 64;
         remaining_len -= 64;
     }
 
     if (remaining_len > 0) {
         memcpy(ctx->buffer, data + data_offset, remaining_len);
     }
     ctx->buffer_len = remaining_len;
 }
 
 void sm3_final(sm3_ctx_t *ctx, unsigned char digest[32]) {
     ctx->buffer[ctx->buffer_len++] = 0x80;
     if (ctx->buffer_len > 56) {
         memset(ctx->buffer + ctx->buffer_len, 0, 64 - ctx->buffer_len);
         sm3_compress(ctx);
         memset(ctx->buffer, 0, 56);
     } else {
         memset(ctx->buffer + ctx->buffer_len, 0, 56 - ctx->buffer_len);
     }
 
     uint64_t bit_len = ctx->total_len * 8;
     uint32_to_be((uint32_t)(bit_len >> 32), ctx->buffer + 56);
     uint32_to_be((uint32_t)(bit_len), ctx->buffer + 60);
 
     sm3_compress(ctx);
 
     for (int i = 0; i < 8; i++) {
         uint32_to_be(ctx->state[i], digest + i * 4);
     }
 }
 
 void sm3_hash(const unsigned char *data, size_t len, unsigned char digest[32]) {
     sm3_ctx_t ctx;
     sm3_init(&ctx);
     sm3_update(&ctx, data, len);
     sm3_final(&ctx, digest);
 }
 
 // --- Special Function for Length-Extension Attack (The Missing Piece) ---
 
 void sm3_init_with_state(sm3_ctx_t *ctx, const uint32_t initial_state[8], uint64_t total_len_bytes) {
     // Copy the provided state instead of the standard IV
     memcpy(ctx->state, initial_state, sizeof(uint32_t) * 8);
     // Set the total length to the length of the original message plus its padding
     ctx->total_len = total_len_bytes;
     // The buffer is initially empty
     ctx->buffer_len = 0;
 }
 