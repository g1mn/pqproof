package edge

import "crypto/tls"

var Config = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
