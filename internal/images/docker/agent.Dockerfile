FROM node:20-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		python3 python3-pip git curl ca-certificates ripgrep jq procps \
	&& rm -rf /var/lib/apt/lists/*

# Harden /etc: replace the full passwd/shadow/group with a single sandbox
# user. TLS certs, nsswitch.conf, and other system files are preserved.
# This runs as root during image build, so we have write access.
RUN echo 'node:x:1000:1000::/workspace:/bin/bash' > /etc/passwd \
	&& echo '' > /etc/shadow \
	&& echo 'node:x:1000:' > /etc/group

RUN usermod -s /bin/bash node \
	&& mkdir -p /workspace \
	&& chown -R node:node /workspace

# Install the AEGIS workspace-jail wrapper as /bin/sh.
# We use mv (atomic rename) to avoid "Text file busy" — the build
# shell still references the old inode, but new processes get the wrapper.
RUN cp /bin/sh /bin/sh.real \
	&& printf '#!/bin/bash\n\
source /tmp/.aegis-jailrc 2>/dev/null\n\
case "${1:-}" in\n\
  -c) eval "$2"; exit $? ;;\n\
  -s) shift; cat | bash --rcfile /tmp/.aegis-jailrc; exit $? ;;\n\
  *) exec /bin/sh.real "$@" ;;\n\
esac\n' > /tmp/sh-jail \
	&& chmod 755 /tmp/sh-jail \
	&& mv /tmp/sh-jail /bin/sh

USER node
WORKDIR /workspace

CMD ["sleep", "infinity"]
