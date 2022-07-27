#! /usr/bin/env bash

echo "Starting aesm service"
wait_time=7
echo "Wait $wait_time seconds for aesm service fully start"
NAME=aesm_service AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service
sleep $wait_time
ps -ef | grep aesm | grep -v grep

echo ""
echo "Starting cess-kaleido"
ENCLAVE_KEY_SEED="TEST_SEED" RUST_LOG="debug" RUST_BACKTRACE=1 /kaleido/app
