ARG NODE_IMAGE=docker.io/library/node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df
FROM ${NODE_IMAGE}
ARG SOURCE_DIGEST
LABEL ai.zinii.source-digest=${SOURCE_DIGEST}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
COPY migrations ./migrations
USER 10001:2000
ENV NODE_ENV=production
ENTRYPOINT ["node", "scripts/start.mjs"]
