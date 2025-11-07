#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "pqc_jni.h"

#define SIG_ALG "Dilithium2"

JNIEXPORT jbyteArray JNICALL Java_org_hyperledger_besu_crypto_PQCJNI_pqcKeypair(JNIEnv *env, jclass cls) {
    const char* SIG_ALGs[] = {
        "Dilithium2", 
        "Dilithium3",
        "Dilithium5"
    };
    OQS_SIG *sig = OQS_SIG_new(SIG_ALGs[0]);
    if(!sig){
        printf("Create signature fail!");
        return NULL;
    }
    size_t pk_len = sig->length_public_key;
    size_t sk_len = sig->length_secret_key;

    uint8_t *pk_chunk = malloc(pk_len);
    uint8_t *sk_chunk = malloc(sk_len);

    if(!pk_chunk || !sk_chunk){
        printf("Create key area fail!");
        OQS_SIG_free(sig);
        free(pk_chunk);
        free(sk_chunk);
        return NULL;
    }
    if (OQS_SUCCESS != sig->keypair(pk_chunk, sk_chunk)) {
        OQS_SIG_free(sig);
        free(pk_chunk); 
        free(sk_chunk);
        return NULL;
    }
    printf("Create key area success!");
    // Pack pk and sk return to JNI
    size_t total_len = pk_len + sk_len + 8;
    uint8_t *package = malloc(total_len);
    if(!package){
        printf("Fail to allocate package area!");
        OQS_SIG_free(sig);
        free(pk_chunk);
        free(sk_chunk);
        return NULL;
    }
    // Insert first 8 bytes = pk_len and sk_len (big endian)
    //pk_len
    package[0] = (pk_len >> 24) & 0xFF;
    package[1] = (pk_len >> 16) & 0xFF;
    package[2] = (pk_len >> 8) & 0xFF;
    package[3] = pk_len & 0xFF;
    //sk_len
    package[4] = (sk_len >> 24) & 0xFF;
    package[5] = (sk_len >> 16) & 0xFF;
    package[6] = (sk_len >> 8) & 0xFF;
    package[7] = sk_len & 0xFF;
    // Copy pk_chunk and sk_chunk to package
    memcpy(package+8, pk_chunk, pk_len);
    memcpy(package+pk_len+8, sk_chunk, sk_len);

    jbyteArray ret = (*env)->NewByteArray(env, total_len);
    (*env)->SetByteArrayRegion(env, ret, 0, total_len, (jbyte *)package);
    
    OQS_SIG_free(sig);
    free(pk_chunk);
    free(sk_chunk);
    free(package);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_hyperledger_besu_crypto_PQCJNI_pqcSign(JNIEnv *env, jclass cls, jbyteArray msg, jbyteArray sk_in) {
    if(!msg || !sk_in){
        printf("Arguments missed or equal to NULL");
        return NULL;
    }
    jsize mlen = (*env)->GetArrayLength(env, msg);
    jbyte *mbuf = (*env)->GetByteArrayElements(env, msg, NULL);

    jsize sk_len = (*env)->GetArrayLength(env, sk_in);
    jbyte *skbuf = (*env)->GetByteArrayElements(env, sk_in, NULL);
    // Allocate new sig
    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (sig == NULL) goto err;

    size_t sig_len = sig->length_signature;
    uint8_t *signature = malloc(sig_len);
    size_t out_sig_len = 0;

    if (OQS_SUCCESS != OQS_SIG_sign(sig, signature, &out_sig_len, (uint8_t *)mbuf, (size_t)mlen, (uint8_t *)skbuf)) {
        free(signature);
        OQS_SIG_free(sig);
        goto err;
    }

    jbyteArray ret = (*env)->NewByteArray(env, out_sig_len);
    (*env)->SetByteArrayRegion(env, ret, 0, out_sig_len, (jbyte *)signature);

    free(signature);
    OQS_SIG_free(sig);
    (*env)->ReleaseByteArrayElements(env, msg, mbuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, sk_in, skbuf, JNI_ABORT);
    return ret;

err:
    if (mbuf) (*env)->ReleaseByteArrayElements(env, msg, mbuf, JNI_ABORT);
    if (skbuf) (*env)->ReleaseByteArrayElements(env, sk_in, skbuf, JNI_ABORT);
    return NULL;
}

JNIEXPORT jboolean JNICALL Java_org_hyperledger_besu_crypto_PQCJNI_pqcVerify(JNIEnv *env, jclass cls, jbyteArray msg, jbyteArray sig_in, jbyteArray pk_in) {
    if (msg == NULL || sig_in == NULL || pk_in == NULL) return JNI_FALSE;

    jsize mlen = (*env)->GetArrayLength(env, msg);
    jbyte *mbuf = (*env)->GetByteArrayElements(env, msg, NULL);

    jsize slen = (*env)->GetArrayLength(env, sig_in);
    jbyte *sbuf = (*env)->GetByteArrayElements(env, sig_in, NULL);

    jsize plen = (*env)->GetArrayLength(env, pk_in);
    jbyte *pbuf = (*env)->GetByteArrayElements(env, pk_in, NULL);

    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (sig == NULL) goto v_err;

    int ok = OQS_SIG_verify(sig, (uint8_t *)mbuf, (size_t)mlen, (uint8_t *)sbuf, (size_t)slen, (uint8_t *)pbuf);

    OQS_SIG_free(sig);
    (*env)->ReleaseByteArrayElements(env, msg, mbuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, sig_in, sbuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, pk_in, pbuf, JNI_ABORT);

    return ok == OQS_SUCCESS ? JNI_TRUE : JNI_FALSE;

v_err:
    if (mbuf) (*env)->ReleaseByteArrayElements(env, msg, mbuf, JNI_ABORT);
    if (sbuf) (*env)->ReleaseByteArrayElements(env, sig_in, sbuf, JNI_ABORT);
    if (pbuf) (*env)->ReleaseByteArrayElements(env, pk_in, pbuf, JNI_ABORT);
    return JNI_FALSE;
}
