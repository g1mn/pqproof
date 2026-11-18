package demo.sealer;

import java.security.Signature;

class Composite {
    Signature signer() throws Exception {
        return Signature.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC");
    }
}
