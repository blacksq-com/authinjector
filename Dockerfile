# Built by .github/workflows/release.yml from the release binaries (static
# musl, no runtime), so the image is the same binary as the tarball.
# TLS roots are compiled in (rustls + webpki-roots), so scratch is enough.
FROM scratch
ARG TARGETARCH
COPY dist/${TARGETARCH}/authinjector /usr/local/bin/authinjector
COPY catalogue.toml /usr/share/authinjector/catalogue.toml
ENTRYPOINT ["/usr/local/bin/authinjector"]
CMD ["serve", "--socket", "/run/authinjector/authinjector.sock", "--catalogue", "/usr/share/authinjector/catalogue.toml", "--config", "/etc/authinjector/config.toml"]
