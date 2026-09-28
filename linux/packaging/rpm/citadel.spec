Name:           citadel
Version:        0.1.0
Release:        1%{?dist}
Summary:        Outbound firewall for Linux desktops
License:        MIT
URL:            https://github.com/NeatOuk/citadel-app
Source0:        citadel-app-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  make
BuildRequires:  python3
BuildRequires:  systemd-rpm-macros
Requires:       python3
Requires:       python3-pyside6
Requires:       qt6-qtdeclarative
Requires:       iproute
Requires:       libnotify
Recommends:     citadel-helper >= 1.3.0
Recommends:     python3-maxminddb
Recommends:     libsecret

%description
Citadel shows which apps connect where, asks at the gate when something new
wants out (in its window or as a notification), and turns your verdicts into
per-app policies. With citadel-helper it enforces them with nftables and can
route chosen apps through HTTP, HTTPS or SOCKS5 proxies.

%prep
%autosetup -n citadel-app-%{version}

%build

%install
make install DESTDIR=%{buildroot} PREFIX=%{_prefix}
rm -rf %{buildroot}%{_datadir}/licenses

%files
%license LICENSE
%{_bindir}/citadel
%{_bindir}/citadel-app
%{_bindir}/citadel-daemon
%{_prefix}/lib/citadel/libexec/
%{_datadir}/citadel/
%{_userunitdir}/citadel.service
%{_datadir}/applications/io.github.neatouk.Citadel.desktop
%{_datadir}/icons/hicolor/scalable/apps/io.github.neatouk.Citadel.svg
%config(noreplace) %{_sysconfdir}/xdg/autostart/io.github.neatouk.Citadel-tray.desktop

%changelog
* Mon Sep 28 2026 Neat Ouk <neatk13@gmail.com> - 0.1.0-1
- First standalone release
