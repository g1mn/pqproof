/* nist_sign_wrap.c: 참조 구현의 접두사 붙은 서명 함수를 NIST API 이름(crypto_sign_*)으로 내보낸다.
   -DWRAP_PREFIX=<접두사> 와 -DWRAP_STYLE_HAETAE(이름 keypair·signature·sign·verify·open, _internal 판도 있음) 또는
   -DWRAP_STYLE_AIMER(이름 crypto_sign_keypair·crypto_sign_signature·crypto_sign·crypto_sign_verify·crypto_sign_open)를 준다.
   ctx 인자를 받는 꼴(ML-DSA 와 같은 꼴)이다. 함수 몸은 그대로 넘기기만 한다. tests/kpqc_targets.sh 가 쓴다(시험용, PQ-Proof 런타임은 쓰지 않는다). */
#include <stddef.h>
#include <stdint.h>
#define WCAT2(a, b) a##b
#define WCAT(a, b) WCAT2(a, b)
#define NS(s) WCAT(WRAP_PREFIX, s)
#define EXPORT __attribute__((visibility("default")))
#if defined(WRAP_STYLE_HAETAE)
#define F_KEYPAIR NS(keypair)
#define F_SIGNATURE NS(signature)
#define F_SIGN NS(sign)
#define F_VERIFY NS(verify)
#define F_OPEN NS(open)
int NS(keypair_internal)(uint8_t *vk, uint8_t *sk, uint8_t seed[32]);
int NS(signature_internal)(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen,
                           const uint8_t rnd[32], const uint8_t *sk);
int NS(verify_internal)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen,
                        const uint8_t *vk);
/* KAT 재생용: PQCgenKAT_sign.c 는 keypair_internal(seed)·signature_internal(pre, rnd)를 부른다(pre = ctxlen || ctx) */
EXPORT int crypto_sign_keypair_internal(uint8_t *vk, uint8_t *sk, uint8_t seed[32]) { return NS(keypair_internal)(vk, sk, seed); }
EXPORT int crypto_sign_signature_internal(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *pre,
                                          size_t prelen, const uint8_t rnd[32], const uint8_t *sk) {
  return NS(signature_internal)(sig, siglen, m, mlen, pre, prelen, rnd, sk);
}
EXPORT int crypto_sign_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pre,
                                       size_t prelen, const uint8_t *vk) {
  return NS(verify_internal)(sig, siglen, m, mlen, pre, prelen, vk);
}
#elif defined(WRAP_STYLE_AIMER)
#define F_KEYPAIR NS(crypto_sign_keypair)
#define F_SIGNATURE NS(crypto_sign_signature)
#define F_SIGN NS(crypto_sign)
#define F_VERIFY NS(crypto_sign_verify)
#define F_OPEN NS(crypto_sign_open)
#else
#error "WRAP_STYLE_HAETAE 또는 WRAP_STYLE_AIMER 를 준다"
#endif
int F_KEYPAIR(uint8_t *pk, uint8_t *sk);
int F_SIGNATURE(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int F_SIGN(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int F_VERIFY(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
int F_OPEN(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
EXPORT int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) { return F_KEYPAIR(pk, sk); }
EXPORT int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                                 const uint8_t *sk) {
  return F_SIGNATURE(sig, siglen, m, mlen, ctx, ctxlen, sk);
}
EXPORT int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk) {
  return F_SIGN(sm, smlen, m, mlen, ctx, ctxlen, sk);
}
EXPORT int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *pk) {
  return F_VERIFY(sig, siglen, m, mlen, ctx, ctxlen, pk);
}
EXPORT int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *ctx, size_t ctxlen,
                            const uint8_t *pk) {
  return F_OPEN(m, mlen, sm, smlen, ctx, ctxlen, pk);
}
