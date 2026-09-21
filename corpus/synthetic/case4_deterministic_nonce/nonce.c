// Synthetic mutation case 4 (spike/PHASE_D.md, D1): an RFC 6979-style
// deterministic nonce derivation. This is the CORRECT, recommended
// construction (README "Sink taxonomy") -- both inputs are the message
// hash and the private key, never fresh entropy, so a same-message-and-key
// call always produces the same nonce on purpose. Flagging this as an
// entropy-critical sink would be exactly the elementary error the project
// README calls out; the point of this case is to prove the taxonomy
// actually prevents that rather than merely documenting the intent.
#include <string.h>

static void hmac_sha256_stub(
    const unsigned char *key, int keylen,
    const unsigned char *msg, int msglen,
    unsigned char *out
) {
    // Elided: a real implementation is genuine HMAC-SHA256. What matters
    // for this test is the call shape (deterministic function of key+msg),
    // not cryptographic correctness of the stub.
    (void)keylen; (void)msglen;
    for (int i = 0; i < 32; i++) {
        out[i] = key[i % 8] ^ msg[i % 8] ^ (unsigned char)i;
    }
}

// RFC 6979 5.2/5.3 in miniature: k is derived deterministically from the
// private key and the message hash via an HMAC-DRBG-shaped construction.
// No call to any RNG anywhere in this function.
void rfc6979_nonce(const unsigned char *privkey_32, const unsigned char *msg_hash_32, unsigned char *nonce_out_32) {
    unsigned char v[32];
    memset(v, 0x01, 32);
    hmac_sha256_stub(privkey_32, 32, msg_hash_32, 32, v);
    hmac_sha256_stub(v, 32, msg_hash_32, 32, nonce_out_32);
}
