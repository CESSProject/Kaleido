include $(top_srcdir)/build-aux/sgx_tlib.am

libdir = $(prefix)/lib64
includedir = $(prefix)/include/pbc

AUTOMAKE_OPTIONS = subdir-objects

ARITH_SOURCES = arith/field.c arith/z.c \
	arith/naivefp.c arith/fastfp.c \
	arith/fp.c arith/fasterfp.c arith/montfp.c \
	arith/ternary_extension_field.c \
	arith/multiz.c \
	arith/dlog.c \
	arith/fieldquadratic.c arith/poly.c \
	arith/random.c arith/init_random.c

ECC_SOURCES = ecc/mpc.c ecc/mnt.c ecc/hilbert.c ecc/curve.c ecc/pairing.c \
ecc/singular.c \
ecc/eta_T_3.c \
ecc/param.c ecc/a_param.c ecc/d_param.c ecc/e_param.c \
ecc/f_param.c ecc/g_param.c

MISC_SOURCES = misc/darray.c misc/symtab.c misc/get_time.c \
misc/utils.c misc/memory.c misc/pbc_sgx_ext.c

include_HEADERS = include/pbc_a_param.h include/pbc_a1_param.h include/pbc_curve.h \
	include/pbc_d_param.h include/pbc_e_param.h include/pbc_f_param.h \
	include/pbc_field.h include/pbc_fieldquadratic.h include/pbc_fp.h \
	include/pbc_g_param.h include/pbc_hilbert.h include/pbc_i_param.h \
	include/pbc_memory.h include/pbc_mnt.h include/pbc_multiz.h \
	include/pbc_pairing.h include/pbc_param.h include/pbc_poly.h \
	include/pbc_random.h include/pbc_singular.h include/pbc_ternary_extension_field.h \
	include/pbc_utils.h include/pbc_z.h include/pbc.h include/pbc_sgx_ext.h include/pbc_init_random.h

lib_LIBRARIES = libsgx_tpbc.a
libsgx_tpbc_a_CFLAGS = -I$(top_srcdir)/include -fno-builtin-memset -fPIC
libsgx_tpbc_a_SOURCES = $(ARITH_SOURCES) $(ECC_SOURCES) $(MISC_SOURCES)
