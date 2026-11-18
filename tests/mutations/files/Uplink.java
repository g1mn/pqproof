package demo.sealer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** Sends sealed records to the archive host. */
final class Uplink {
    SSLSocket open(String host, int port) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.1");
        ctx.init(null, null, null);
        SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
        s.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
        return s;
    }
}
