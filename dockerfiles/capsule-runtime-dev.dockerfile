FROM scratch

COPY ./capsule-runtime /usr/local/bin/capsule-runtime

ENTRYPOINT ["/usr/local/bin/capsule-runtime"]