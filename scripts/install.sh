#!/bin/bash

source ./utils.sh
source ./install_build_dep.sh
source ./install_sgx.sh

function kaleido_help()
{
cat << EOF

Options:
	help					display help information
	sgx				        install sgx driver
		<dcap>				install DCAP driver
		<isgx>				install isgx driver
	uninstall				uninstall your phala scripts
	build_dep               install Kaleido build dependencies GMP/PBC/etc 
EOF
exit 0
}

if [ $(id -u) -ne 0 ]; then
	echo "Please run with sudo!"
	exit 1
fi

case "$1" in
	sgx)
		sgx $2
		;;
	build_dep)
		install_build_dep $2
		;;
	uninstall)
		uninstall
		;;
	*)
		kaleido_help
		;;
esac

exit 0
