/*
 * File: sm3.h
 * Description: Header file for the basic SM3 hash implementation.
 * It defines the context structure and function prototypes for the SM3 algorithm.
 */
 #ifndef SM3_H
 #define SM3_H
 
 #include <stdint.h>
 #include <stddef.h>
 
 // 定义SM3上下文结构体
 // 用于支持流式哈希计算 (分块更新)
 typedef struct {
     uint32_t state[8];      // 中间哈希值 (A, B, C, D, E, F, G, H)
     uint64_t total_len;     // 已处理数据的总长度 (以字节为单位)
     unsigned char buffer[64]; // 未处理数据的缓冲区，大小为一个分组
     size_t buffer_len;      // 缓冲区中当前数据的长度
 } sm3_ctx_t;
 
 /* --- 标准 SM3 函数 --- */
 
 /**
  * @brief 初始化SM3上下文
  * @param ctx 指向要初始化的上下文的指针
  */
 void sm3_init(sm3_ctx_t *ctx);
 
 /**
  * @brief 更新哈希值 (可以多次调用)
  * @param ctx 指向SM3上下文的指针
  * @param data 指向输入数据的指针
  * @param len 输入数据的长度
  */
 void sm3_update(sm3_ctx_t *ctx, const unsigned char *data, size_t len);
 
 /**
  * @brief 完成哈希计算并输出结果
  * @param ctx 指向SM3上下文的指针
  * @param digest 用于存储32字节哈希结果的数组
  */
 void sm3_final(sm3_ctx_t *ctx, unsigned char digest[32]);
 
 /**
  * @brief 一体化函数，直接计算数据的哈希值
  * @param data 指向输入数据的指针
  * @param len 输入数据的长度
  * @param digest 用于存储32字节哈希结果的数组
  */
 void sm3_hash(const unsigned char *data, size_t len, unsigned char digest[32]);
 
 
 /* --- 长度扩展攻击所需的特殊函数 --- */
 
 /**
  * @brief 使用一个已知的状态初始化SM3上下文
  * @param ctx 指向要初始化的上下文的指针
  * @param initial_state 一个包含8个32位整数的数组，用作初始哈希值
  * @param total_len_bytes 已经处理过的原始消息的总长度（字节），用于后续的填充
  */
 void sm3_init_with_state(sm3_ctx_t *ctx, const uint32_t initial_state[8], uint64_t total_len_bytes);
 
 #endif // SM3_H
 