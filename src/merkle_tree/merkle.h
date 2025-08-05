#ifndef MERKLE_H
#define MERKLE_H

#include "sm3.h"

#define HASH_SIZE 32

// 树节点结构体
typedef struct MerkleNode {
    unsigned char hash[HASH_SIZE];
    struct MerkleNode *left;
    struct MerkleNode *right;
    struct MerkleNode *parent; // 指向父节点，方便生成证明
} MerkleNode;

// 函数原型
MerkleNode* create_node(const unsigned char* hash);
MerkleNode* build_merkle_tree(MerkleNode** leaves, int count);
void free_merkle_tree(MerkleNode* node);

int get_existence_proof(MerkleNode* root, const unsigned char* target_hash, 
                        unsigned char proof[][HASH_SIZE], int proof_path[], int* proof_len);

int verify_existence_proof(const unsigned char* leaf_hash, const unsigned char* root_hash, 
                           const unsigned char proof[][HASH_SIZE], const int proof_path[], int proof_len);

#endif // MERKLE_H
