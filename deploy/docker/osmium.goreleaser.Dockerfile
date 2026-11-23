FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/osmium /usr/local/bin/osmium
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/osmium"]
CMD ["server", "-c", "/etc/osmium/server.json"]
