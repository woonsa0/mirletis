#include "mirletis.h"

int main() {
    mir_pk_t pk;
    mir_sk_t sk;
    mir_ct_t ct;
    uint8_t k1[32], k2[32];
    uint8_t entropy[32] = { /* ... random bytes ... */ };

    // Simple API
    mir_keygen(&pk, &sk, entropy);
    mir_encaps(&ct, k1, &pk, entropy); // Use fresh entropy for encaps
    mir_decaps(k2, &ct, &sk);

    // k1 and k2 are now identical.
    return 0;
}
