/*
 * File: attack.c
 * Description: Implements the logic for the SM3 length-extension attack.
 */
 #include <stdio.h>
 #include <string.h>
 #include <stdint.h>
 #include "sm3.h" // 依赖 sm3.h 接口
 
 // 字节序转换 (大端)
 static void uint64_to_be(uint64_t n, unsigned char *dst) {
     dst[0] = (n >> 56) & 0xFF;
     dst[1] = (n >> 48) & 0xFF;
     dst[2] = (n >> 40) & 0xFF;
     dst[3] = (n >> 32) & 0xFF;
     dst[4] = (n >> 24) & 0xFF;
     dst[5] = (n >> 16) & 0xFF;
     dst[6] = (n >> 8) & 0xFF;
     dst[7] = n & 0xFF;
 }
 
 /**
  * @brief 伪造SM3哈希
  * @param original_len 原始消息(secret || message)的总字节长度
  * @param original_hash 原始消息的哈希结果 H(secret || message)
  * @param new_data 攻击者想要附加的新数据
  * @param new_data_len 新数据的长度
  * @param forged_hash [输出] 伪造的哈希 H(secret || message || padding || new_data)
  * @param forged_message_suffix [输出] 伪造消息的后缀 (padding || new_data)
  * @param forged_message_suffix_len [输出] 伪造消息后缀的长度
  */
 int forge_sm3(size_t original_len, const unsigned char original_hash[32],
               const unsigned char *new_data, size_t new_data_len,
               unsigned char forged_hash[32],
               unsigned char *forged_message_suffix, size_t *forged_message_suffix_len)
 {
     // 1. 构造填充 (Padding)
     // 这是哈希算法在处理原始消息时会添加的填充
     unsigned char padding[128];
     size_t padding_len = 0;
 
     // a. 添加 0x80
     padding[padding_len++] = 0x80;
 
     // b. 计算需要填充多少个0字节
     //    目标是使 (original_len + 1 + k) % 64 == 56
     size_t k = (56 - ((original_len + 1) % 64) + 64) % 64;
     memset(padding + padding_len, 0, k);
     padding_len += k;
 
     // c. 附上原始消息的位长度 (64位大端)
     uint64_t bit_len = original_len * 8;
     uint64_to_be(bit_len, padding + padding_len);
     padding_len += 8;
 
     // 2. 构造伪造消息的后缀
     //    这个后缀就是 (padding || new_data)
     memcpy(forged_message_suffix, padding, padding_len);
     memcpy(forged_message_suffix + padding_len, new_data, new_data_len);
     *forged_message_suffix_len = padding_len + new_data_len;
 
     // 3. 伪造哈希
     sm3_ctx_t ctx;
     
     // a. 将已知的原始哈希值转换为32位整数数组，作为初始状态
     uint32_t initial_state[8];
     for (int i = 0; i < 8; i++) {
         initial_state[i] = (original_hash[i*4]   << 24) | 
                            (original_hash[i*4+1] << 16) | 
                            (original_hash[i*4+2] << 8)  | 
                            (original_hash[i*4+3]);
     }
     
     // b. 使用这个特殊状态和填充后的长度来初始化哈希上下文
     //    填充后的长度为 original_len + padding_len
     uint64_t new_start_len = original_len + padding_len;
     sm3_init_with_state(&ctx, initial_state, new_start_len);
 
     // c. 更新附加数据
     sm3_update(&ctx, new_data, new_data_len);
 
     // d. 计算最终的伪造哈希
     sm3_final(&ctx, forged_hash);
 
     return 0;
 }
 