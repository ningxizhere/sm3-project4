/*
 * File: tests/test_attack.c
 * Description: Test driver for the SM3 length-extension attack.
 * This file contains the main function to set up the scenario and run the attack.
 */
 #include <stdio.h>
 #include <string.h>
 #include "sm3.h" // 依赖基础SM3实现
 
 // 需要包含攻击逻辑的头文件 (你需要创建 attack.h)
 // 为了简化，我们直接在这里声明函数原型
 int forge_sm3(size_t original_len, const unsigned char original_hash[32],
               const unsigned char *new_data, size_t new_data_len,
               unsigned char forged_hash[32],
               unsigned char *forged_message, size_t *forged_message_len);
 
 // 打印摘要的辅助函数
 static void print_hash(const char* label, const unsigned char hash[32]) {
     printf("%s: ", label);
     for (int i = 0; i < 32; i++) {
         printf("%02x", hash[i]);
     }
     printf("\n");
 }
 
 int main() {
     // --- 场景设置 ---
     const unsigned char secret[] = "this_is_a_very_secret_key";
     const unsigned char message[] = "user=guest&role=viewer";
     const unsigned char new_data[] = "&role=admin&action=delete";
     
     size_t secret_len = strlen((const char*)secret);
     size_t message_len = strlen((const char*)message);
     size_t new_data_len = strlen((const char*)new_data);
 
     // --- 合法用户的操作 ---
     // 构造原始消息: secret || message
     unsigned char original_data[256];
     memcpy(original_data, secret, secret_len);
     memcpy(original_data + secret_len, message, message_len);
     size_t original_data_len = secret_len + message_len;
 
     // 计算原始消息的哈希值
     unsigned char original_hash[32];
     sm3_hash(original_data, original_data_len, original_hash);
     
     printf("--- Legitimate User Side ---\n");
     printf("Original Data (secret || message) has length %zu\n", original_data_len);
     print_hash("Original Hash (known to attacker)", original_hash);
     printf("\n");
 
     // --- 攻击者的操作 ---
     // 攻击者知道: `message`, `original_hash`, `secret_len` (但不知道`secret`本身)
     printf("--- Attacker Side ---\n");
     printf("Known message: '%s'\n", message);
     printf("Known secret length: %zu\n", secret_len);
     printf("Data to append: '%s'\n", new_data);
 
     unsigned char forged_message_suffix[256];
     size_t forged_message_suffix_len;
     unsigned char forged_hash[32];
 
     // 调用攻击函数
     forge_sm3(original_data_len, original_hash, new_data, new_data_len,
               forged_hash, forged_message_suffix, &forged_message_suffix_len);
 
     printf("--> Forged Hash (computed without secret): ");
     print_hash("", forged_hash);
 
     // --- 验证攻击 ---
     printf("\n--- Verification Side ---\n");
     // 服务器端用真实的secret来构造完整的伪造消息
     unsigned char full_forged_data[512];
     // 1. 原始部分
     memcpy(full_forged_data, original_data, original_data_len);
     // 2. 攻击者生成的后缀 (padding + new_data)
     memcpy(full_forged_data + original_data_len, forged_message_suffix, forged_message_suffix_len);
     size_t full_forged_data_len = original_data_len + forged_message_suffix_len;
 
     // 计算这个完整伪造消息的真实哈希值
     unsigned char verification_hash[32];
     sm3_hash(full_forged_data, full_forged_data_len, verification_hash);
     printf("--> Verification Hash (computed with secret): ");
     print_hash("", verification_hash);
 
     // 比较两个哈希值
     if (memcmp(forged_hash, verification_hash, 32) == 0) {
         printf("\n[SUCCESS] The forged hash matches the verification hash. Attack successful!\n");
     } else {
         printf("\n[FAILURE] The hashes do not match. Attack failed.\n");
     }
 
     return 0;
 }
 