#
# Makefile for the SM3 Project
#

# --- 编译器和编译选项 ---
# CC: C 编译器
# CFLAGS: C 编译器的通用选项
#   -Wall -Wextra: 显示所有常用和额外的警告，帮助发现潜在问题
#   -O2:          二级优化，在保证编译速度的同时提供很好的性能
#   -std=c99:     使用C99标准
# SIMD_FLAGS: 针对SIMD代码的特殊选项
#   -mavx2:       启用AVX2指令集
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
SIMD_FLAGS = -mavx2

# --- 路径定义 (关键部分) ---
# INCLUDES: 定义头文件的搜索路径
#   -I<path> 告诉编译器去 <path> 目录寻找 #include "..." 的文件
#   有了下面这行，编译器在编译任何文件时，都会自动去 ./src/sm3_basic/
#   和 ./src/merkle_tree/ 目录寻找头文件，从而解决报错问题。
INCLUDES = -I./src/sm3_basic -I./src/merkle_tree

# --- 源代码文件 ---
# 将所有源文件路径定义为变量，方便管理
SM3_BASIC_SRC = src/sm3_basic/sm3.c
SM3_UNROLLED_SRC = src/sm3_optimized/sm3_unrolled.c
SM3_SIMD_SRC = src/sm3_optimized/sm3_simd.c
ATTACK_SRC = src/length_extension_attack/attack.c
MERKLE_SRC = src/merkle_tree/merkle.c

# --- 测试文件 ---
TEST_SM3 = tests/test_sm3.c
TEST_ATTACK = tests/test_attack.c
TEST_MERKLE = tests/test_merkle.c

# --- 编译目标 ---

# 'all' 是默认目标，当你只输入 'make' 命令时，它会被执行
# 它依赖于所有我们想要生成的可执行文件
all: test_sm3_basic test_sm3_unrolled test_sm3_simd test_attack test_merkle

# 目标1: 编译基础版SM3测试程序
# $@: 代表目标文件名 (test_sm3_basic)
# $^: 代表所有依赖文件
test_sm3_basic: $(TEST_SM3) $(SM3_BASIC_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(INCLUDES)

# 目标2: 编译循环展开优化版的SM3测试程序
# 注意：它也使用 tests/test_sm3.c 作为测试驱动
test_sm3_unrolled: $(TEST_SM3) $(SM3_UNROLLED_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(INCLUDES)

# 目标3: 编译SIMD优化版的SM3测试程序
# 注意：编译时需要加上 SIMD_FLAGS
test_sm3_simd: $(TEST_SM3) $(SM3_SIMD_SRC)
	$(CC) $(CFLAGS) $(SIMD_FLAGS) -o $@ $^ $(INCLUDES)

# 目标4: 编译长度扩展攻击测试程序
test_attack: $(TEST_ATTACK) $(ATTACK_SRC) $(SM3_BASIC_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(INCLUDES)

# 目标5: 编译Merkle树测试程序
test_merkle: $(TEST_MERKLE) $(MERKLE_SRC) $(SM3_BASIC_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(INCLUDES)


# --- 清理目标 ---

# 'clean' 用于删除所有编译生成的文件，保持目录整洁
.PHONY: all clean
clean:
	rm -f test_sm3_basic test_sm3_unrolled test_sm3_simd test_attack test_merkle

