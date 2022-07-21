if [ $SDK_DIST != "SELF_BUILT" ]; then
    cd /root && \
    curl -o sdk.sh $SDK_URL && \
    chmod a+x /root/sdk.sh && \
    echo -e 'no\n/opt' | ./sdk.sh && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    . /opt/sgxsdk/environment && \
    cd /root && \
    rm ./sdk.sh; \
    rm /root/03_sdk.sh
else
    cd /root && \
    git clone --recursive https://github.com/intel/linux-sgx && \
    cd linux-sgx && \
    git checkout sgx_2.15.1 && \
    ./download_prebuilt.sh && \
    make -j "$(nproc)" sdk_install_pkg && \
    echo -e 'no\n/opt' | ./linux/installer/bin/sgx_linux_x64_sdk_2.15.101.1.bin && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    . /opt/sgxsdk/environment && \
    cd /root && \
    rm -rf /root/linux-sgx; \
    rm /root/03_sdk.sh
fi
