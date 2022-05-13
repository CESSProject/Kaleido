#!/bin/bash

if [ $(id -u) -ne 0 ]; then
	echo "Please run with sudo!"
	exit 1
fi

if [ $(lsb_release -r | grep -o "[0-9]*\.[0-9]*") == "18.04" ]; then
	dcap_driverurl="https://download.01.org/intel-sgx/latest/dcap-latest/linux/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.41.bin"
	dcap_driverbin="sgx_linux_x64_driver_1.41.bin"
	isgx_driverurl="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.11.054c9c4c.bin"
	isgx_driverbin="sgx_linux_x64_driver_2.11.054c9c4c.bin"
elif [ $(lsb_release -r | grep -o "[0-9]*\.[0-9]*") = "20.04" ]; then
	dcap_driverurl="https://download.01.org/intel-sgx/latest/dcap-latest/linux/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin"
	dcap_driverbin="sgx_linux_x64_driver_1.41.bin"
	isgx_driverurl="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_driver_2.11.054c9c4c.bin"
	isgx_driverbin="sgx_linux_x64_driver_2.11.054c9c4c.bin"
else
	log_err "Your system is not supported. Kaleido currently only supports Ubuntu 18.04/Ubuntu 20.04"
	exit 1
fi

function install_sgx_depenencies() {
	log_info "Apt update"
	apt-get update
	if [ $? -ne 0 ]; then
		log_err "Apt update failed"
		exit 1
	fi

	log_info "Install dependencies"
	for i in $(seq 0 4); do
		for package in jq curl wget unzip zip docker docker-compose node yq dkms; do
			if ! type $package >/dev/null; then
				case $package in
				jq | curl | wget | unzip | zip | dkms)
					apt-get install -y $package
					;;
				docker)
					curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
					add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
					apt-get install -y docker-ce docker-ce-cli containerd.io
					usermod -aG docker $USER
					;;
				docker-compose)
					curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
					chmod +x /usr/local/bin/docker-compose
					;;
				node)
					curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
					apt-get install -y nodejs
					;;
				yq)
					wget https://github.com/mikefarah/yq/releases/download/v4.11.2/yq_linux_amd64.tar.gz -O /tmp/yq_linux_amd64.tar.gz
					tar -xvf /tmp/yq_linux_amd64.tar.gz -C /tmp
					mv /tmp/yq_linux_amd64 /usr/bin/yq
					rm /tmp/yq_linux_amd64.tar.gz
					;;
				*)
					break
					;;
				esac
			fi
		done
		if type jq curl wget unzip zip docker docker-compose node yq dkms >/dev/null; then
			break
		else
			log_err "Failed to install dependencies, please check installation logs"
			exit 1
		fi
	done
}

function remove_dirver() {
	if [ -f /opt/intel/sgxdriver/uninstall.sh ]; then
		log_info "Remove dcap/isgx driver"
		/opt/intel/sgxdriver/uninstall.sh
	fi
}

function install_dcap() {
	log_info "Download dcap driver"
	for i in $(seq 0 4); do
		wget $dcap_driverurl -O /tmp/$dcap_driverbin
		if [ $? -ne 0 ]; then
			log_err "Download isgx dirver failed, try again!"
		else
			break
		fi
	done

	if [ -f /tmp/$dcap_driverbin ]; then
		log_info "Give dcap driver executable permission"
		chmod +x /tmp/$dcap_driverbin
	else
		log_err "The DCAP driver was not successfully downloaded, please check your network!"
		exit 1
	fi

	log_info "Installing dcap driver"
	/tmp/$dcap_driverbin
	if [ $? -ne 0 ]; then
		log_err "Failed to install the DCAP driver, please check the driver's installation logs!"
		exit 1
	else
		log_success "Delete temporary files"
		rm /tmp/$dcap_driverbin
	fi

	return 0
}

function install_isgx() {
	log_info "Download isgx driver"
	for i in $(seq 0 4); do
		wget $isgx_driverurl -O /tmp/$isgx_driverbin
		if [ $? -ne 0 ]; then
			log_err "Download isgx dirver failed"
		else
			break
		fi
	done

	if [ -f /tmp/$isgx_driverbin ]; then
		log_info "Give isgx driver executable permission"
		chmod +x /tmp/$isgx_driverbin
	else
		log_err "The isgx driver was not successfully downloaded, please check your network!"
		exit 1
	fi

	log_info "Installing isgx driver"
	/tmp/$isgx_driverbin
	if [ $? -ne 0 ]; then
		log_err "Failed to install the isgx driver, please check the driver installation logs!"
		exit 1
	else
		log_success "Deleteted temporary files"
		rm /tmp/$isgx_driverbin
	fi

	return 0
}

function install_driver() {
	remove_dirver
	install_dcap
	if [ $? -ne 0 ]; then
		install_isgx
		if [ $? -ne 0 ]; then
			log_err "Failed to install the DCAP and isgx driver, please check the driver installation logs!"
			exit 1
		fi
	fi
}

function sgx() {
	case "$1" in
	"")
		install_sgx_depenencies
		install_driver
		;;
	dcap)
		install_dcap
		;;
	isgx)
		install_isgx
		;;
	*)
		kaleido_help
		exit 1
		;;
	esac

	if [ -L /dev/sgx/enclave ] && [ -L /dev/sgx/provision ] && [ -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ] && [ ! -c /dev/isgx ]; then
		log_info "Your device exists: /dev/sgx/enclave /dev/sgx/provision /dev/sgx_enclave /dev/sgx_provision is related to the DCAP driver"
	elif [ ! -L /dev/sgx/enclave ] && [ -L /dev/sgx/provision ] && [ -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ] && [ ! -c /dev/isgx ]; then
		log_info "Your device exists: /dev/sgx/provision /dev/sgx_enclave /dev/sgx_provision is related to the DCAP driver"
	elif [ ! -L /dev/sgx/enclave ] && [ ! -L /dev/sgx/provision ] && [ -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ] && [ ! -c /dev/isgx ]; then
  	log_info "Your device exists: /dev/sgx_enclave /dev/sgx_provision is related to the DCAP driver"
	elif [ ! -L /dev/sgx/enclave ] && [ ! -L /dev/sgx/provision ] && [ ! -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ] && [ ! -c /dev/isgx ]; then
		log_info "Your device exists: /dev/sgx_provision is related to the DCAP driver"
	elif [ ! -L /dev/sgx/enclave ] && [ ! -L /dev/sgx/provision ] && [ ! -c /dev/sgx_enclave ] && [ ! -c /dev/sgx_provision ] && [ -c /dev/isgx ]; then
		log_info "Your device exists: /dev/isgx is related to the isgx driver"
	else
		log_info "The DCAP/isgx driver file was not found, please check the driver installation logs!"
		exit 1
	fi
}
