/* nist_kem_wrap.c: 참조 구현의 접두사 붙은 KEM 함수(WRAP_PREFIX##keypair 등)를 NIST API 이름(crypto_kem_*)으로 내보낸다.
   tests/kpqc_targets.sh 가 -DWRAP_PREFIX=cryptolab_smaugt_mode3_ 처럼 접두사를 주어 빌드한다(시험용, PQ-Proof 런타임은 쓰지 않는다).
   함수 몸은 그대로 넘기기만 한다. -DWRAP_PLANT_DEFECT 를 주면 decaps 결과의 첫 바이트를 바꾼다(시험이 잡아야 하는 일부러 틀린 빌드). */
#include <stddef.h>
#include <stdint.h>
#define WCAT2(a, b) a##b
#define WCAT(a, b) WCAT2(a, b)
#define NS(s) WCAT(WRAP_PREFIX, s)
#define EXPORT __attribute__((visibility("default")))
int NS(keypair)(uint8_t *pk, uint8_t *sk);
int NS(enc)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int NS(dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
EXPORT int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) { return NS(keypair)(pk, sk); }
EXPORT int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return NS(enc)(ct, ss, pk); }
EXPORT int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  int r = NS(dec)(ss, ct, sk);
#if defined(WRAP_PLANT_DEFECT)
  ss[0] ^= 1; /* planted defect */
#endif
  return r;
}
