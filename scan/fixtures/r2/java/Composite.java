Signature s = Signature.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC");
ECKey k = new ECKeyGenerator(Curve.P_256).generate();
