ooppkcs11rs
-----
Pronounced "oops" as in, "oops, you're using PKCS#11".

This is a rust implementation of a PKCS#11 module that will load another PKCS#11
module in a separate process. The eventual goal is that this provides a safe(r)
way of providing PKCS#11 support. If a 3rd party module hangs or crashes, the
incorporating application should be able to recover.

Due to library dependencies, this doesn't currently work on Windows.

Due to not developing on OS X, this probably doesn't work on OS X.
