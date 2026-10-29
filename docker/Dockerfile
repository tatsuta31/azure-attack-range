# Toolbox image for azure-attack-range.
# Unlike upstream's Dockerfile, this does NOT git clone attack_range (upstream clones
# the default branch = v5). The vendored+patched v4.0.2 source is bind-mounted at /work.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip curl ca-certificates openssh-client sshpass jq vim less \
    && rm -rf /var/lib/apt/lists/*

# Terraform: same version upstream v4.0.2 pins
ARG TERRAFORM_VERSION=1.9.8
RUN curl -fsSL https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -o /tmp/tf.zip \
    && unzip /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip

# Azure CLI in its own venv so its azure-* deps don't fight attack_range's pinned ones
RUN python -m venv /opt/azcli \
    && /opt/azcli/bin/pip install azure-cli \
    && ln -s /opt/azcli/bin/az /usr/local/bin/az

# attack_range v4.0.2 python deps (ansible 10.4.0 bundles the windows collections)
COPY attack_range/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# SSH: don't prompt for host keys of freshly built VMs
RUN mkdir -p /etc/ssh/ssh_config.d \
    && printf 'Host *\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile /root/.ssh/known_hosts\n' > /etc/ssh/ssh_config.d/lab.conf

WORKDIR /work/attack_range
CMD ["bash"]
