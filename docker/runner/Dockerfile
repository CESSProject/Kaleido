FROM cesslab/cess-sgxrust-pbc-env:latest as builder

WORKDIR /kaleido-build
COPY . .
RUN make

FROM cesslab/cess-sgxrust-pbc-env:latest

WORKDIR /kaleido
COPY --from=builder /kaleido-build/bin/ /kaleido/
ADD docker/runner/start.sh /kaleido/

CMD [ "/kaleido/start.sh" ]
