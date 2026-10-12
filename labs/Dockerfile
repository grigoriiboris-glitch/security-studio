FROM mongo:4.4-focal

ARG NODE22_VERSION=22.23.3
ARG NODE12_VERSION=12.22.12
ARG NODEGOAT_COMMIT=c5cb68a7084e4ae7dcc60e6a98768720a81841e8
ARG JUICE_SHOP_VERSION=20.3.0

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl git xz-utils \
  && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  case "$(dpkg --print-architecture)" in \
    amd64) NODE_ARCH=x64; JUICE_ARCH=x64; JUICE_SHA=6148dcce8fe7d990a86bf8457a0e9a07821c127d498c76da1a3bc7dba12a77e5 ;; \
    arm64) NODE_ARCH=arm64; JUICE_ARCH=arm64; JUICE_SHA=7983185bdeebed72e7f8b2a281f96e883ce4cf1dae7718cb37817c62baae2ca9 ;; \
    *) echo "Unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
  esac; \
  NODE22_ARCHIVE="node-v$NODE22_VERSION-linux-$NODE_ARCH.tar.xz"; \
  NODE12_ARCHIVE="node-v$NODE12_VERSION-linux-$NODE_ARCH.tar.xz"; \
  curl -fsSL "https://nodejs.org/dist/v$NODE22_VERSION/SHASUMS256.txt" -o /tmp/node22-shasums.txt; \
  curl -fsSL "https://nodejs.org/dist/v$NODE22_VERSION/$NODE22_ARCHIVE" -o "/tmp/$NODE22_ARCHIVE"; \
  grep " $NODE22_ARCHIVE$" /tmp/node22-shasums.txt | (cd /tmp && sha256sum -c -); \
  mkdir -p /opt/node22; tar -xJf "/tmp/$NODE22_ARCHIVE" -C /opt/node22 --strip-components=1; \
  curl -fsSL "https://nodejs.org/dist/v$NODE12_VERSION/SHASUMS256.txt" -o /tmp/node12-shasums.txt; \
  curl -fsSL "https://nodejs.org/dist/v$NODE12_VERSION/$NODE12_ARCHIVE" -o "/tmp/$NODE12_ARCHIVE"; \
  grep " $NODE12_ARCHIVE$" /tmp/node12-shasums.txt | (cd /tmp && sha256sum -c -); \
  mkdir -p /opt/node12; tar -xJf "/tmp/$NODE12_ARCHIVE" -C /opt/node12 --strip-components=1; \
  curl -fsSL "https://github.com/juice-shop/juice-shop/releases/download/v$JUICE_SHOP_VERSION/juice-shop-$JUICE_SHOP_VERSION"_node22_linux_"$JUICE_ARCH".tgz -o /tmp/juice-shop.tgz; \
  echo "$JUICE_SHA  /tmp/juice-shop.tgz" | sha256sum -c -; \
  mkdir -p /opt/juice-shop; tar -xzf /tmp/juice-shop.tgz -C /opt/juice-shop --strip-components=1; \
  mkdir -p /opt/juice-shop/data-bundled; mv /opt/juice-shop/data/static /opt/juice-shop/data-bundled/static; \
  git init /opt/nodegoat; \
  git -C /opt/nodegoat remote add origin https://github.com/OWASP/NodeGoat.git; \
  git -C /opt/nodegoat fetch --depth 1 origin "$NODEGOAT_COMMIT"; \
  git -C /opt/nodegoat checkout --detach FETCH_HEAD; \
  cd /opt/nodegoat; \
  PATH="/opt/node12/bin:$PATH" CYPRESS_INSTALL_BINARY=0 npm install --unsafe-perm --no-audit --no-fund; \
  mkdir -p /opt/juice-shop/logs; \
  chown -R mongodb:mongodb /opt/nodegoat /opt/juice-shop; \
  rm -rf /tmp/node22* /tmp/node12* /tmp/juice-shop.tgz /var/lib/apt/lists/* /opt/nodegoat/.git

ENV PATH="/opt/node22/bin:$PATH"
ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /opt
COPY entrypoint.sh /usr/local/bin/security-labs-entrypoint
RUN chmod 0755 /usr/local/bin/security-labs-entrypoint
USER mongodb
EXPOSE 3000 4000
ENTRYPOINT ["/usr/local/bin/security-labs-entrypoint"]
CMD ["juice-shop"]
