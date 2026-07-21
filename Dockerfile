FROM node:22.22.0-bookworm-slim@sha256:7cc56ef285a8568121537d17b05e72128f01b89c54607b51acf084a50ef483f3 AS browser

ARG TARGETARCH
ARG CHROME_VERSION=151.0.7922.34
ARG CHROME_SHA256=ae8736ac28bc69278551500f219fc749575648263c43ec5990749eff43b9fcf8
ARG CHROME_URL=https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.34/linux64/chrome-linux64.zip

RUN test "$TARGETARCH" = "amd64" \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates curl fonts-liberation libasound2 libatk-bridge2.0-0 \
    libatk1.0-0 libcairo2 libcups2 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0 \
    libgtk-3-0 libnspr4 libnss3 libpango-1.0-0 libudev1 libvulkan1 \
    libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxkbcommon0 libxrandr2 unzip xdg-utils \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "$CHROME_URL" -o /tmp/chrome.zip \
  && echo "$CHROME_SHA256  /tmp/chrome.zip" | sha256sum -c - \
  && unzip -q /tmp/chrome.zip -d /opt \
  && mv /opt/chrome-linux64 /opt/chrome \
  && rm /tmp/chrome.zip \
  && /opt/chrome/chrome --version | grep -F "$CHROME_VERSION"

ENV XSS_VERIFIER_BROWSER_PATH=/opt/chrome/chrome
ENV XSS_VERIFIER_EXPECTED_BROWSER_VERSION=${CHROME_VERSION}

FROM browser AS build

WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY .gitignore .oxfmtrc.json .oxlintrc.json tsconfig.json tsconfig.build.json ./
COPY scripts ./scripts
COPY src ./src
ENV XSS_VERIFIER_INTEGRATION=1
ENV XSS_VERIFIER_BROWSER_SANDBOX=disabled
RUN npm run check

FROM browser AS runtime

ARG VCS_REF=local
LABEL org.opencontainers.image.title="xss-verifier" \
  org.opencontainers.image.description="Deterministic browser replay for self-contained XSS proofs" \
  org.opencontainers.image.source="https://github.com/awebench/xss-verifier" \
  org.opencontainers.image.revision="$VCS_REF" \
  org.opencontainers.image.version="0.1.0" \
  org.opencontainers.image.licenses="Apache-2.0" \
  io.xss-verifier.contract-version="1" \
  io.xss-verifier.chrome-version="151.0.7922.34"

RUN useradd --create-home --shell /bin/sh verifier \
  && mkdir -p /opt/xss-verifier /tests /logs/verifier /work \
  && chown -R verifier:verifier /logs/verifier /work

WORKDIR /opt/xss-verifier
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
  && npm cache clean --force
COPY --from=build /workspace/dist ./dist
COPY test.sh /tests/test.sh
RUN chmod 755 /tests/test.sh

ENV XSS_VERIFIER_BROWSER_SANDBOX=disabled
USER verifier
WORKDIR /work
CMD ["node", "/opt/xss-verifier/dist/cli.js"]
