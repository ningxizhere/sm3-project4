/*
 * File: test_sm3.c
 * Description: Test suite for SM3 implementations.
 * It uses standard test vectors to verify the correctness of the hash output.
 */
 #include <stdio.h>
 #include <string.h>
 #include "sm3.h" // Include the header for your SM3 implementation
 
 // Helper function to print a hash digest
 void print_digest(const unsigned char *digest) {
     for (int i = 0; i < 32; i++) {
         printf("%02x", digest[i]);
     }
     printf("\n");
 }
 
 // A single test case structure
 typedef struct {
     const char *input;
     const char *expected_output;
 } sm3_test_case;
 
 // Standard SM3 test vectors
 sm3_test_case test_vectors[] = {
     {
         "abc",
         "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
     },
     {
         "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
     }
 };
 
 int main() {
     int num_tests = sizeof(test_vectors) / sizeof(sm3_test_case);
     int passed_tests = 0;
     unsigned char digest[32];
 
     printf("Running SM3 implementation tests...\n\n");
 
     for (int i = 0; i < num_tests; i++) {
         const sm3_test_case *tc = &test_vectors[i];
         const unsigned char *input_data = (const unsigned char *)tc->input;
         size_t input_len = strlen(tc->input);
 
         printf("Test Case %d:\n", i + 1);
         printf("Input: \"%s\"\n", tc->input);
 
         // --- Call your SM3 hash function ---
         sm3_hash(input_data, input_len, digest);
 
         printf("Expected: %s\n", tc->expected_output);
         printf("Got:      ");
         print_digest(digest);
 
         // Convert expected hex string to bytes for comparison
         unsigned char expected_digest[32];
         for(int j=0; j<32; j++) {
             sscanf(tc->expected_output + 2*j, "%2hhx", &expected_digest[j]);
         }
 
         if (memcmp(digest, expected_digest, 32) == 0) {
             printf("Result: PASSED\n\n");
             passed_tests++;
         } else {
             printf("Result: FAILED\n\n");
         }
     }
 
     printf("--- Test Summary ---\n");
     printf("%d out of %d tests passed.\n", passed_tests, num_tests);
 
     return (passed_tests == num_tests) ? 0 : 1;
 }
 