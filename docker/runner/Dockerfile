FROM cesslab/cess-sgxrust-env:latest 

WORKDIR /kaleido
COPY . /kaleido/
RUN /opt/intel/sgx-aesm-service/aesm/linksgx.sh && \
    /bin/mkdir -p /var/run/aesmd/ && \
    /bin/chown -R aesmd:aesmd /var/run/aesmd/ && \
    /bin/chmod 0755 /var/run/aesmd/ && \
    /bin/chown -R aesmd:aesmd /var/opt/aesmd/ && \
    /bin/chmod 0750 /var/opt/aesmd/

CMD [ "/kaleido/start.sh" ]
