# Installs Citadel on Linux (daemon, CLI, app). Packages call: make install DESTDIR=...
# macOS builds live in macos/.
PREFIX  ?= /usr
DESTDIR ?=
VERSION := $(shell python3 -c "import re;print(re.search(r'VERSION = \"(.*)\"', open('citadel/daemon.py').read()).group(1))")
SHARE   := $(DESTDIR)$(PREFIX)/share/citadel
LIBEXEC := $(DESTDIR)$(PREFIX)/lib/citadel/libexec

.PHONY: all install test dist clean
all:

install:
	install -d $(SHARE)/citadel/monitor $(SHARE)/citadel/platform $(SHARE)/app/qml/qs/Commons $(SHARE)/app/qml/qs/Ui $(SHARE)/app/qml/views $(LIBEXEC)
	install -m644 citadel/*.py $(SHARE)/citadel/
	install -m644 citadel/platform/*.py $(SHARE)/citadel/platform/
	install -m644 citadel/monitor/*.py $(SHARE)/citadel/monitor/
	install -m644 app/citadel_app.py $(SHARE)/app/
	install -m644 app/qml/*.qml app/qml/Model.js $(SHARE)/app/qml/
	install -m644 app/qml/qs/Commons/* $(SHARE)/app/qml/qs/Commons/
	install -m644 app/qml/qs/Ui/* $(SHARE)/app/qml/qs/Ui/
	install -m644 app/qml/views/* $(SHARE)/app/qml/views/
	install -m755 libexec/citadel-monitor libexec/citadel-proxy libexec/citadel-explain $(LIBEXEC)/
	install -Dm755 bin/citadel-daemon $(DESTDIR)$(PREFIX)/bin/citadel-daemon
	install -Dm755 bin/citadel $(DESTDIR)$(PREFIX)/bin/citadel
	install -Dm755 bin/citadel-app $(DESTDIR)$(PREFIX)/bin/citadel-app
	install -Dm644 linux/data/citadel.service $(DESTDIR)$(PREFIX)/lib/systemd/user/citadel.service
	install -Dm644 linux/data/io.github.neatouk.Citadel.desktop $(DESTDIR)$(PREFIX)/share/applications/io.github.neatouk.Citadel.desktop
	install -Dm644 linux/data/io.github.neatouk.Citadel-tray.desktop $(DESTDIR)/etc/xdg/autostart/io.github.neatouk.Citadel-tray.desktop
	install -Dm644 data/io.github.neatouk.Citadel.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/io.github.neatouk.Citadel.svg
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/citadel/LICENSE

test:
	python3 -m unittest discover -s tests -t .

dist:
	git archive --format=tar.gz --prefix=citadel-app-$(VERSION)/ -o citadel-app-$(VERSION).tar.gz HEAD
	@echo citadel-app-$(VERSION).tar.gz

clean:
	find . -name __pycache__ -prune -exec rm -rf {} +
