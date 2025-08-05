/*
 * File: tests/test_merkle.c
 * Description: Test driver for the Merkle tree implementation.
 * Builds a large tree and verifies an existence proof for a leaf.
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 #include "merkle.h" // 依赖merkle树的头文件
 
 #define HASH_SIZE 32
 #define LEAF_COUNT 100000
 
 // 打印哈希的辅助函数
 static void print_hash(const unsigned char *hash) {
     for(int i = 0; i < HASH_SIZE; i++) {
         printf("%02x", hash[i]);
     }
 }
 
 int main() {
     srand(time(NULL));
     printf("--- Merkle Tree Test with %d leaves ---\n\n", LEAF_COUNT);
 
     // 1. 创建叶子节点
     printf("1. Generating %d leaf nodes...\n", LEAF_COUNT);
     MerkleNode** leaves = (MerkleNode**)malloc(sizeof(MerkleNode*) * LEAF_COUNT);
     if (!leaves) {
         fprintf(stderr, "Failed to allocate memory for leaves.\n");
         return 1;
     }
 
     for (int i = 0; i < LEAF_COUNT; i++) {
         char data[64];
         // 使用随机数据确保每次运行的哈希都不同
         sprintf(data, "leaf-data-%d-%d", i, rand());
         unsigned char hash[HASH_SIZE];
         sm3_hash((unsigned char*)data, strlen(data), hash);
         leaves[i] = create_node(hash);
     }
     printf("   Done.\n\n");
 
     // 2. 构建树
     printf("2. Building the Merkle tree...\n");
     MerkleNode* root = build_merkle_tree(leaves, LEAF_COUNT);
     if (!root) {
         fprintf(stderr, "Failed to build Merkle tree.\n");
         return 1;
     }
     printf("   Done.\n");
     printf("   Merkle Root Hash: ");
     print_hash(root->hash);
     printf("\n\n");
 
     // 3. 为一个随机选择的叶子生成存在性证明
     int target_leaf_index = rand() % LEAF_COUNT;
     unsigned char* target_leaf_hash = leaves[target_leaf_index]->hash;
 
     printf("3. Generating existence proof for leaf #%d...\n", target_leaf_index);
     printf("   Target Leaf Hash: ");
     print_hash(target_leaf_hash);
     printf("\n");
 
     // 证明路径最多为树的高度
     unsigned char proof[64][HASH_SIZE];
     int proof_len = 0;
     int proof_path[64]; // 0 for left, 1 for right
 
     // 调用生成证明的函数
     if (!get_existence_proof(root, target_leaf_hash, proof, proof_path, &proof_len)) {
         fprintf(stderr, "Failed to generate proof for leaf %d.\n", target_leaf_index);
         return 1;
     }
     printf("   Proof generated with %d steps.\n\n", proof_len);
 
     // 4. 验证存在性证明
     printf("4. Verifying the existence proof...\n");
     int is_valid = verify_existence_proof(target_leaf_hash, root->hash, proof, proof_path, proof_len);
     
     if (is_valid) {
         printf("   [SUCCESS] Verification successful! The leaf is proven to be in the tree.\n");
     } else {
         printf("   [FAILURE] Verification failed! The proof is incorrect.\n");
     }
     
     // 5. 清理内存 (非常重要)
     // free_merkle_tree(root);
     // free(leaves);
 
     return 0;
 }
 