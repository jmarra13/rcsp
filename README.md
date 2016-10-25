# rcsp
Revised CSP perl script to manage a small private CA - based on CSP-0.3.4

This is a command line driven application.

This script is a small wrapper around OpenSSL which allows simple administration of
a small private CA for internal PKI usage.  It likely will not scale well but for
small organisations requires a publiclly accessable CP and CSP together with downloadable
PEM and DER formats for fewer than several hundred generated certificates this 
should suffice.
