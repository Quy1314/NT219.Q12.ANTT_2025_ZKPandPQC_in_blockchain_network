#ifndef PQC_JNI_H
#define PQC_JNI_H

#include <jni.h>

JNIEXPORT jbyteArray JNICALL Java_org_hyperledger_besu_crypto_PQCJNI_pqcKeypair(JNIEnv *, jclass);
JNIEXPORT jbyteArray JNICALL Java_org_hyperledger_besu_crypto_PQCJNI_pqcSign(JNIEnv *, jclass, jbyteArray, jbyteArray);
JNIEXPORT jboolean JNICALL Java_org_hyperledger_besu_crypto_PQCJNI_pqcVerify(JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

#endif 
