AC_INIT(libsgx_pbc, 0.1, cyx.xjtu@gmail.com)

AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AM_PROG_CC_C_O

AC_PROG_RANLIB

CFLAGS=
default_fink_path=/sw
case $host_os in
     darwin*)
	      dnl fink installation
     	      AC_MSG_CHECKING([for a fink installation at $default_fink_path])
     	      if test -d $default_fink_path; then
	      	 AC_MSG_RESULT([found it!])
		 AC_MSG_NOTICE([Adding -I$default_fink_path/include to CPPFLAGS])
	      	 CPPFLAGS="-I$default_fink_path/include $CPPFLAGS"
		 AC_MSG_NOTICE([Adding -L$default_fink_path/lib to LDFLAGS])
		 LDFLAGS="-L$default_fink_path/lib $LDFLAGS"
	      else
		AC_MSG_RESULT(none)
		AC_MSG_NOTICE([You may need to add set CPPFLAGS and LDFLAGS for gmp, etc.])
	      fi
	      ;;
esac

with_enable_optimized="no"
AC_ARG_ENABLE( optimized,
              [AS_HELP_STRING([--enable-optimized],
                              [Enable optimized build])],
              [with_enable_optimized="$withval"],
              [with_enable_optimized="no"])


with_safe_clean=n
AC_ARG_ENABLE( safe-clean,
              [AS_HELP_STRING([--enable-safe-clean],
                              [When free any PBC element or GMP mpz_t, fill internal memory inside the element by zero])],
              [with_safe_clean=y],
              [with_safe_clean=n])

with_debug=n
AC_ARG_ENABLE( debug,
              [AS_HELP_STRING([--enable-debug],
                              [Add extra debugging information. Forbid compiling optimization.])],
                              [with_debug=y],
                              [with_debug=n])

CFLAGS="$CFLAGS -Wall -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wredundant-decls \
-Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -std=gnu99 ${ac_cv_sgx_tlib_cppflags} -nostdinc"
if test "$with_debug" == "y"; then
    CFLAGS="$CFLAGS -g3 -O0"
elif test "$with_enable_optimized" != "no"; then
   	CFLAGS="$CFLAGS -g -O2"
else
	CFLAGS="$CFLAGS -fomit-frame-pointer -O3"
fi

if test "$with_safe_clean" != "n"; then
  CFLAGS="$CFLAGS -DSAFE_CLEAN"
fi

PBC_WITH_DEBUG="#define __DEBUG__"
AC_SUBST(PBC_WITH_DEBUG)

SGX_INIT()

lib_err_msg="add its path to LDFLAGS\nsee ./configure --help"
SGX_TSTDC_CHECK_LIB([m], [pow], [], [
                  echo "************************"
                  echo "m library not found"
                  echo -e $lib_err_msg
                  echo "************************"
                  exit -1
                  ])

SGX_TSTDC_CHECK_HEADERS([stdlib.h string.h sys/time.h])
SGX_TSTDC_CHECK_FUNCS([floor gettimeofday memmove memset pow sqrt strchr strdup])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT()
