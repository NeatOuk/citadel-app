#!/bin/sh
# Build (and install-test) Citadel's .deb or .rpm in a throwaway container.
#   packaging/build-in-docker.sh deb [image]   (default debian:trixie)
#   packaging/build-in-docker.sh rpm [image]   (default fedora:latest)
# Output lands in packaging/out/. Inside the container the package is
# installed and `citadel-daemon --selftest` plus the unit tests run.
set -e
kind=$1; here=$(cd "$(dirname "$0")/.." && pwd); out="$here/packaging/out"; mkdir -p "$out"
ver=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$here/citadel/daemon.py")
case "$kind" in
  deb) img=${2:-debian:trixie}
    docker run --rm -v "$here:/src:ro" -v "$out:/out" "$img" sh -ec '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq && apt-get install -y -qq debhelper make python3 git >/dev/null
      cp -r /src /build && cd /build && rm -rf debian && cp -r packaging/debian debian
      dpkg-buildpackage -us -uc -b >/dev/null && cp ../citadel_*.deb /out/
      apt-get install -y -qq ../citadel_*.deb >/dev/null
      citadel-daemon --selftest || true
      python3 -c "import PySide6.QtQuick; print(\"PySide6\", PySide6.__version__)"
      cd /build && QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -t . 2>&1 | tail -3
      echo "installed: $(dpkg-query -W citadel)"' ;;
  rpm) img=${2:-fedora:latest}
    docker run --rm -v "$here:/src:ro" -v "$out:/out" "$img" sh -ec "
      dnf -q -y install rpm-build make python3 systemd-rpm-macros git >/dev/null
      mkdir -p ~/rpmbuild/SOURCES && cd /src && git -c safe.directory=/src archive --format=tar.gz --prefix=citadel-app-$ver/ -o ~/rpmbuild/SOURCES/citadel-app-$ver.tar.gz HEAD
      rpmbuild -bb packaging/rpm/citadel.spec >/dev/null && cp ~/rpmbuild/RPMS/noarch/citadel-*.rpm /out/
      dnf -q -y install ~/rpmbuild/RPMS/noarch/citadel-*.rpm >/dev/null
      citadel-daemon --selftest || true
      cd /src && QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -t . 2>&1 | tail -3
      echo installed: \$(rpm -q citadel)" ;;
  *) echo "usage: $0 deb|rpm [image]"; exit 2 ;;
esac
