AC_PREREQ(2.58)
AC_INIT(certwatch, 1.1)
AC_CHECK_PROGS(XMLTO, [xmlto], [:])
AC_CHECK_LIB(crypto, X509_get_subject_name,,
             [AC_ERROR(libcrypto not found)])
AC_CONFIG_FILES(Makefile)
AC_OUTPUT

