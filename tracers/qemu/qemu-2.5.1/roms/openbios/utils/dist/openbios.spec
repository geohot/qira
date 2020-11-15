#
# spec file for package openbios
#

Name:         openbios
Version:      0.1
Release:      0
Summary:      OpenBIOS development utilities
License:      GNU General Public License (GPL) - all versions, Other License(s), see package
Group:        Development/Tools/Other
Autoreqprov:  on
# Scripts and programs
Source0:      OpenBIOS.tar.bz2
BuildRoot:    %{_tmppath}/%{name}-%{version}-build

%description
This package contains the OpenBIOS development utilities.

There are
* toke - an IEEE 1275-1994 compliant FCode tokenizer
* detok - an IEEE 1275-1994 compliant FCode detokenizer
* paflof - a forth kernel running in user space
* an fcode bytecode evaluator running in paflof

See /usr/share/doc/packages/openbios for details and examples.

Authors:
--------
    Stefan Reinauer <stepan@openbios.net>
    Segher Boessenkool <segher@openbios.net>

%prep
%setup -n openbios

%build
( cd toke; make; strip toke )
( cd detok; make; strip detok )
( cd paflof; make; strip paflof )
( find toke/examples -name .cvsignore | xargs rm -f )

%install
rm -rf		 ${RPM_BUILD_ROOT}
mkdir -p	 ${RPM_BUILD_ROOT}/usr/bin/
mkdir -p	 ${RPM_BUILD_ROOT}/usr/share/openbios
mkdir -p	 ${RPM_BUILD_ROOT}/usr/share/doc/packages/openbios
cp toke/toke	 ${RPM_BUILD_ROOT}/usr/bin/
cp detok/detok	 ${RPM_BUILD_ROOT}/usr/bin/
cp paflof/paflof ${RPM_BUILD_ROOT}/usr/bin/
cp -a toke/examples	${RPM_BUILD_ROOT}/usr/share/doc/packages/openbios
cp -a forth 		${RPM_BUILD_ROOT}/usr/share/openbios
cp toke/README	 ${RPM_BUILD_ROOT}/usr/share/doc/packages/openbios/README.toke
cp detok/README	 ${RPM_BUILD_ROOT}/usr/share/doc/packages/openbios/README.detok

%files
/usr/bin
/usr/share/openbios
%doc /usr/share/doc/packages/openbios

%changelog -n openbios
* Mon Jul 22 2002 - stepan@suse.de
- initial version
