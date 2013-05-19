AM_CFLAGS = \
  $(GLIB_CFLAGS) \
  -I$(top_srcdir)/sjson \
  -I$(top_srcdir)

noinst_LTLIBRARIES = libtools.la

libtools_la_SOURCES = \
  tools.c \
  tools.h

LDADD = \
  libtools.la \
  $(top_builddir)/mega/libmega.la \
  $(GLIB_LIBS)

megafs_LDADD = \
  $(LDADD) \
  $(FUSE_LIBS)

megafs_CFLAGS = \
  $(AM_CFLAGS) \
  $(FUSE_CFLAGS)

bin_PROGRAMS = megareg megadf # megals megamkdir megamv megarm # megadl megaget megaput megasync

megadf_SOURCES     = df.c
megadl_SOURCES     = dl.c
megaget_SOURCES    = get.c
megals_SOURCES     = ls.c
megamkdir_SOURCES  = mkdir.c
megaput_SOURCES    = put.c
megareg_SOURCES    = reg.c
megarm_SOURCES     = rm.c
megamv_SOURCES     = mv.c
megasync_SOURCES   = sync.c

if ENABLE_FUSE
#bin_PROGRAMS += megafs
megafs_SOURCES     = fs.c
endif
