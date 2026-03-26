/*
 * ===========================================================================
 * Professional Forensics Container — Quantum Verify v2.1.0
 * ML-DSA-65 (Dilithium) Signature Verifier
 * Usa liboqs (Open Quantum Safe) — NIST FIPS 204
 *
 * Compilar:
 *   gcc -o quantum_verify quantum_verify.c \
 *       -loqs -I/usr/local/include -L/usr/local/lib
 *
 * Uso:
 *   quantum_verify <chave_privada> <chave_publica> <desafio>
 *
 * Retorna:
 *   stdout: "SUCCESS" se assinatura válida
 *   exit 0: sucesso
 *   exit 1: falha
 * ===========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define ML_DSA_65 OQS_SIG_alg_ml_dsa_65

static void secure_free(void *ptr, size_t len) {
    if (ptr) {
        memset(ptr, 0, len);
        free(ptr);
    }
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        fprintf(stderr, "Uso: %s <chave_privada> <chave_publica> <desafio>\n",
                argv[0]);
        fprintf(stderr, "Exemplo: %s /keys/priv.key /keys/pub.key \"challenge_hex\"\n",
                argv[0]);
        return 1;
    }

    const char *sk_path   = argv[1];
    const char *pk_path   = argv[2];
    const char *challenge = argv[3];
    size_t challenge_len  = strlen(challenge);

    /* Inicializar esquema ML-DSA-65 */
    OQS_SIG *sig = OQS_SIG_new(ML_DSA_65);
    if (sig == NULL) {
        fprintf(stderr, "ERRO: Falha ao inicializar ML-DSA-65\n");
        fprintf(stderr, "      Verifique se liboqs está instalado corretamente\n");
        return 1;
    }

    /* Alocar memória para chaves */
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *signature  = malloc(sig->length_signature);

    if (!secret_key || !public_key || !signature) {
        fprintf(stderr, "ERRO: Falha ao alocar memória\n");
        OQS_SIG_free(sig);
        return 1;
    }

    /* Ler chave privada */
    FILE *sk_file = fopen(sk_path, "rb");
    if (!sk_file) {
        fprintf(stderr, "ERRO: Não foi possível abrir chave privada: %s\n", sk_path);
        secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        return 1;
    }
    size_t sk_read = fread(secret_key, 1, sig->length_secret_key, sk_file);
    fclose(sk_file);

    if (sk_read != sig->length_secret_key) {
        fprintf(stderr, "ERRO: Chave privada inválida (tamanho: %zu, esperado: %zu)\n",
                sk_read, sig->length_secret_key);
        secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        return 1;
    }

    /* Ler chave pública */
    FILE *pk_file = fopen(pk_path, "rb");
    if (!pk_file) {
        fprintf(stderr, "ERRO: Não foi possível abrir chave pública: %s\n", pk_path);
        secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        return 1;
    }
    size_t pk_read = fread(public_key, 1, sig->length_public_key, pk_file);
    fclose(pk_file);

    if (pk_read != sig->length_public_key) {
        fprintf(stderr, "ERRO: Chave pública inválida (tamanho: %zu, esperado: %zu)\n",
                pk_read, sig->length_public_key);
        secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        return 1;
    }

    /* Assinar o desafio com a chave privada */
    size_t signature_len = 0;
    OQS_STATUS sign_status = OQS_SIG_sign(
        sig,
        signature, &signature_len,
        (const uint8_t *)challenge, challenge_len,
        secret_key
    );

    /* Limpar chave privada da memória imediatamente após uso */
    secure_free(secret_key, sig->length_secret_key);
    secret_key = NULL;

    if (sign_status != OQS_SUCCESS) {
        fprintf(stderr, "ERRO: Falha ao assinar o desafio\n");
        free(public_key);
        secure_free(signature, sig->length_signature);
        OQS_SIG_free(sig);
        return 1;
    }

    /* Verificar a assinatura com a chave pública */
    OQS_STATUS verify_status = OQS_SIG_verify(
        sig,
        (const uint8_t *)challenge, challenge_len,
        signature, signature_len,
        public_key
    );

    /* Limpar dados sensíveis da memória */
    free(public_key);
    secure_free(signature, sig->length_signature);
    OQS_SIG_free(sig);

    if (verify_status != OQS_SUCCESS) {
        fprintf(stderr, "FALHA: Verificação de assinatura ML-DSA-65 falhou\n");
        return 1;
    }

    /* Sucesso — imprimir resultado para o script quantum-root */
    printf("SUCCESS\n");
    return 0;
}
