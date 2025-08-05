/*
 * File: merkle.c
 * Description: Implements a Merkle tree using the SM3 hash algorithm.
 * This is the library part, containing functions for building the tree,
 * creating proofs, and verifying proofs.
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "merkle.h"
 
 // 创建新节点
 MerkleNode* create_node(const unsigned char* hash) {
     MerkleNode* node = (MerkleNode*)malloc(sizeof(MerkleNode));
     if (!node) return NULL;
     memcpy(node->hash, hash, HASH_SIZE);
     node->left = NULL;
     node->right = NULL;
     node->parent = NULL;
     return node;
 }
 
 // 释放树的内存
 void free_merkle_tree(MerkleNode* node) {
     if (!node) return;
     free_merkle_tree(node->left);
     free_merkle_tree(node->right);
     free(node);
 }
 
 // 内部函数：计算父节点哈希
 static void hash_parent(const unsigned char* left_hash, const unsigned char* right_hash, unsigned char* parent_hash) {
     unsigned char combined[HASH_SIZE * 2];
     // RFC 6962 要求按字典序合并，以防止二次映像攻击
     if (memcmp(left_hash, right_hash, HASH_SIZE) <= 0) {
         memcpy(combined, left_hash, HASH_SIZE);
         memcpy(combined + HASH_SIZE, right_hash, HASH_SIZE);
     } else {
         memcpy(combined, right_hash, HASH_SIZE);
         memcpy(combined + HASH_SIZE, left_hash, HASH_SIZE);
     }
     sm3_hash(combined, HASH_SIZE * 2, parent_hash);
 }
 
 // 构建Merkle树
 MerkleNode* build_merkle_tree(MerkleNode** leaves, int count) {
     if (count == 0) return NULL;
     if (count == 1) return leaves[0];
 
     MerkleNode** parents = (MerkleNode**)malloc(sizeof(MerkleNode*) * ((count + 1) / 2));
     if (!parents) return NULL;
     int parent_idx = 0;
 
     for (int i = 0; i < count; i += 2) {
         MerkleNode* left = leaves[i];
         MerkleNode* right = (i + 1 < count) ? leaves[i + 1] : left; // 奇数时复制最后一个
 
         unsigned char parent_hash[HASH_SIZE];
         hash_parent(left->hash, right->hash, parent_hash);
 
         MerkleNode* parent = create_node(parent_hash);
         parent->left = left;
         parent->right = right;
         left->parent = parent;
         right->parent = parent;
         parents[parent_idx++] = parent;
     }
 
     MerkleNode* root = build_merkle_tree(parents, parent_idx);
     free(parents);
     return root;
 }
 
 // 内部函数：在树中查找一个哈希对应的叶子节点
 static MerkleNode* find_leaf(MerkleNode* node, const unsigned char* target_hash) {
     if (!node) return NULL;
     if (!node->left && !node->right) { // 是叶子节点
         return (memcmp(node->hash, target_hash, HASH_SIZE) == 0) ? node : NULL;
     }
     MerkleNode* found = find_leaf(node->left, target_hash);
     if (found) return found;
     return find_leaf(node->right, target_hash);
 }
 
 // 生成存在性证明
 int get_existence_proof(MerkleNode* root, const unsigned char* target_hash, 
                         unsigned char proof[][HASH_SIZE], int proof_path[], int* proof_len) {
     *proof_len = 0;
     MerkleNode* leaf_node = find_leaf(root, target_hash);
     if (!leaf_node) return 0; // 没找到
 
     MerkleNode* current = leaf_node;
     while (current->parent) {
         MerkleNode* parent = current->parent;
         if (parent->left == current) { // 当前节点是左孩子
             memcpy(proof[*proof_len], parent->right->hash, HASH_SIZE);
             proof_path[*proof_len] = 1; // 兄弟在右边
         } else { // 当前节点是右孩子
             memcpy(proof[*proof_len], parent->left->hash, HASH_SIZE);
             proof_path[*proof_len] = 0; // 兄弟在左边
         }
         (*proof_len)++;
         current = parent;
     }
     return 1;
 }
 
 // 验证存在性证明
 int verify_existence_proof(const unsigned char* leaf_hash, const unsigned char* root_hash, 
                            const unsigned char proof[][HASH_SIZE], const int proof_path[], int proof_len) {
     unsigned char current_hash[HASH_SIZE];
     memcpy(current_hash, leaf_hash, HASH_SIZE);
 
     for (int i = 0; i < proof_len; i++) {
         unsigned char parent_hash[HASH_SIZE];
         const unsigned char* sibling_hash = proof[i];
 
         if (proof_path[i] == 0) { // 兄弟在左边
             hash_parent(sibling_hash, current_hash, parent_hash);
         } else { // 兄弟在右边
             hash_parent(current_hash, sibling_hash, parent_hash);
         }
         memcpy(current_hash, parent_hash, HASH_SIZE);
     }
 
     return memcmp(current_hash, root_hash, HASH_SIZE) == 0;
 }
 