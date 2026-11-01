ARG NODE_IMAGE
FROM ${NODE_IMAGE}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
USER 10001:2000
ENV NODE_ENV=production
ENTRYPOINT ["node", "scripts/start.mjs"]
