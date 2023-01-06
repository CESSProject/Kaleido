FROM cesslab/cess-sgxrust-env:latest 

WORKDIR /kaleido
COPY . /kaleido/
ARG IAS_API_KEY=""
ENV IAS_API_KEY ${IAS_API_KEY}
ARG IAS_SPID=""
ENV IAS_SPID ${IAS_SPID}
ARG CESS_POST_CHAL_URL=""
ENV CESS_POST_CHAL_URL ${CESS_POST_CHAL_URL}

RUN /opt/intel/sgx-aesm-service/aesm/linksgx.sh && \
    /bin/mkdir -p /var/run/aesmd/ && \
    /bin/chown -R aesmd:aesmd /var/run/aesmd/ && \
    /bin/chmod 0755 /var/run/aesmd/ && \
    /bin/chown -R aesmd:aesmd /var/opt/aesmd/ && \
    /bin/chmod 0750 /var/opt/aesmd/

CMD [ "/kaleido/start.sh" ]
