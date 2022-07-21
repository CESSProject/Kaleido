cd /root; \
set -eux; \
curl 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init' --output /root/rustup-init && \
chmod +x ./rustup-init && \
./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION && \
rm rustup-init; \
chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
rustup --version; \
cargo --version; \
rustc --version;
rustup component add rust-src rls rust-analysis clippy rustfmt && \
cargo install xargo && \
rm -rf $CARGO_HOME/registry; \
rm -rf $CARGO_HOME/git; \
rm /root/05_rust.sh
