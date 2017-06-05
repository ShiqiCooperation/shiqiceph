#!/bin/sh -x

set -e

test -f src/ceph.in || {
    echo "You must run this script in the top-level ceph directory"
    exit 1
}

check_for_pkg_config() {
    which pkg-config >/dev/null && return

    echo
    echo "Error: could not find pkg-config"
    echo
    echo "Please make sure you have pkg-config installed."
    echo
    exit 1
}

if [ `which libtoolize` ]; then
    LIBTOOLIZE=libtoolize
elif [ `which glibtoolize` ]; then
    LIBTOOLIZE=glibtoolize
else
  echo "Error: could not find libtoolize"
  echo "  Please install libtoolize or glibtoolize."
  exit 1
fi

if test -d ".git" ; then
  if ! git submodule sync || ! git submodule update --init; then
    echo "Error: could not initialize submodule projects"
    echo "  Network connectivity might be required."
    exit 1
  fi
fi

rm -f config.cache
aclocal -I m4 --install
check_for_pkg_config
$LIBTOOLIZE --force --copy
aclocal -I m4 --install
autoconf
autoheader
automake -a --add-missing -Wall
( cd src/gmock && autoreconf -fvi; )
( cd src/rocksdb && autoreconf -fvi; )
exit
