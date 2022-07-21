#! /usr/bin/env bash

echo "Starting aesm service"
wait_time=7
echo "Wait $wait_time seconds for aesm service fully start"
/opt/intel/sgx-aesm-service/aesm/linksgx.sh
/bin/mkdir -p /var/run/aesmd/
/bin/chown -R aesmd:aesmd /var/run/aesmd/
/bin/chmod 0755 /var/run/aesmd/
/bin/chown -R aesmd:aesmd /var/opt/aesmd/
/bin/chmod 0750 /var/opt/aesmd/
NAME=aesm_service AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service
sleep $wait_time
ps -ef | grep aesm

echo ""
echo "Starting cess-kaleido"
ENCLAVE_KEY_SEED="TEST_SEED" RUST_LOG="debug" RUST_BACKTRACE=1 /kaleido/app
