Summary: XenTPMServer RPM
Name: xentpm
Version: %{?version}%{!?version:1.0}
Release: %{?release}%{!?release:1}
License: BSD
Group: System/Security
Source: %{name}-%{version}.tar.gz
URL: http://www.citrix.com
Vendor: @COMPANY_NAME_LEGAL@
Requires: trousers, xapi-core
BuildRequires: trousers, trousers-devel
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%define  debug_package %{nil}

%description

%prep
%setup 


%build
%{__make}

#%patch

%install
echo Starting install section
%{__make} install prefix=%{_builddir}

rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/xensource/tpm
mkdir -p %{buildroot}/etc/xapi.d/plugins

cp %{_builddir}/opt/xensource/tpm/* %{buildroot}/opt/xensource/tpm/
cp %{_builddir}/etc/xapi.d/plugins/* %{buildroot}/etc/xapi.d/plugins/

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
echo Cleaning buildroot:%{buildroot}
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/opt/xensource/tpm/*
/etc/xapi.d/plugins/*


%changelog
* Tue Mar 14 2012 Nehal Bandi
- Initial implementation

