Summary: XenTPMServer RPM
Name: xentpm
Version: %{?version}%{!?version:1.0}
Release: %{?release}%{!?release:1}
License: CPL
Group: System/Security
Source: %{name}.tar.gz
URL: http://www.citrix.com
Vendor: @COMPANY_NAME_LEGAL@
Requires: trousers
BuildRoot: %{_tmppath}/%{name}-buildroot

%define  debug_package %{nil}

%description

%prep
%setup 


%build
make CPPFLAGS=-I%{trousers_dir}/include LDFLAGS=-L%{trousers_dir}/lib

#%patch

%install
echo Starting install section
make install prefix=%{_builddir}

rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/tpm
mkdir -p %{buildroot}/etc/xapi.d/plugins

cp %{_builddir}/opt/tpm/* %{buildroot}/opt/tpm/
cp %{_builddir}/etc/xapi.d/plugins/* %{buildroot}/etc/xapi.d/plugins/


%post -p /sbin/ldconfig
/opt/tpm/generateAik
%postun -p /sbin/ldconfig

%clean
echo Cleaning buildroot:%{buildroot}
rm -rf %{buildroot}

%files
/opt/tpm/*
/etc/xapi.d/plugins/*

%defattr(-,root,root,-)

%changelog
* Tue Mar 14 2012 Nehal Bandi
- Initial implementation

