#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// RSA 서명 생성 함수
int generate_rsa_signature(const unsigned char *message, size_t message_len, const char *private_key_path, unsigned char **signature, size_t *signature_len) {
    
	// RSA 변수 생성
	RSA *rsa = NULL;
	
	// Private Key 파일 불러오기
    FILE *private_key_file = fopen(private_key_path, "r");
    if (!private_key_file) {
        printf("Failed to open private key file.\n");
        return -1;
    }

	// Private Key 파일로부터 RSA 추출
    rsa = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (!rsa) {
        printf("Failed to read private key.\n");
        return -1;
    }

	// Hash(메시지 다이제스트) 생성
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, digest);
	
	// 서명 변수 생성
    *signature = (unsigned char *)malloc(RSA_size(rsa));
    if (!signature) {
        printf("Failed to allocate memory for signature.\n");
        RSA_free(rsa);
        return -1;
    }

	// 서명 실행 및 할당
    unsigned int signature_length = 0;
    int result = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, *signature, &signature_length, rsa);
    if (result != 1) {
        printf("Failed to generate RSA signature.\n");
        RSA_free(rsa);
        free(*signature);
        return -1;
    }

	// 메모리 해제
    *signature_len = signature_length;
    RSA_free(rsa);
    return 0;
}

// RSA 서명 검증 함수
int verify_rsa_signature(const unsigned char *message, size_t message_len, const char *public_key_path, const unsigned char *signature, size_t signature_len) {
    
	// RSA 변수 생성
	RSA *rsa = NULL;
	
	// Public Key 파일 불러오기
    FILE *public_key_file = fopen(public_key_path, "r");
    if (!public_key_file) {
        printf("Failed to open public key file.\n");
        return -1;
    }
	
	// Public Key 파일로부터 RSA 추출
    rsa = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);
    if (!rsa) {
        printf("Failed to read public key.\n");
        return -1;
    }

	// Hash(메시지 다이제스트) 생성
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, digest);

	// 서명 검증
    int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, signature_len, rsa);
    if (result != 1) {
        printf("RSA signature verification failed.\n");
        RSA_free(rsa);
        return -1;
    }

	// 메모리 해제
    RSA_free(rsa);
    return 0;
}

int main() {
    // 메시지와 키 경로
    const unsigned char message[] = "Hello, RSA!";
	const unsigned char message2[] = "Goodbye, RSA!"; // 검증 실패용 메시지
    const char private_key_path[] = "/workspace/digisig_c/src/private_key.pem";
    const char public_key_path[] = "/workspace/digisig_c/src/public_key.pem";

    // RSA 서명 생성
    unsigned char *signature;
    size_t signature_len;
    int result = generate_rsa_signature(message2, strlen((const char *)message), private_key_path, &signature, &signature_len);
    
	// RSA 서명 실패 시
	if (result != 0) {
        printf("Failed to generate RSA signature.\n");
        return -1;
    }

    // RSA 서명 검증
	// 서명 생성 시 사용한 메시지 사용 시 검증 성공(message), 다른 메시지 사용 시 검증 실패(message2)
    result = verify_rsa_signature(message, strlen((const char *)message), public_key_path, signature, signature_len);
    
	// RSA 서명 검증 실패 시
	if (result != 0) {
        printf("RSA signature verification failed.\n");
        return -1;
    }
	
	// RAS 서명 검증 성공 문구
    printf("RSA signature verification successful.\n");

    // 서명 메모리 해제
    free(signature);

    return 0;
}