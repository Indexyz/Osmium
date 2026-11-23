FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/osmium-agent /usr/local/bin/osmium-agent
ENTRYPOINT ["/usr/local/bin/osmium-agent"]
CMD ["-c", "/etc/osmium-agent/agent.json"]
