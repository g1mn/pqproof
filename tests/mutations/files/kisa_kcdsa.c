#include "KISA_KCDSA.h"

/* EC-KCDSA signature left in the migrated tree */
int sign_receipt(const unsigned char *msg, int len, unsigned char *sig)
{
    return KISA_KCDSA_sign(0, msg, len, sig);
}
