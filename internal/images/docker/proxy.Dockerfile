FROM scratch

COPY aegis-proxy /aegis-proxy

EXPOSE 3128 53

ENTRYPOINT ["/aegis-proxy"]
