#include "KISA_KCDSA.h"
int sign(void) { return KISA_KCDSA_sign(0, 0, 0, 0); }
int ec_sign(void) { return EC_KCDSA_sign(0, 0); }
