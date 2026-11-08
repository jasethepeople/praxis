FROM oven/bun:1.4.4
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY --chown=bun:bun src ./src
COPY --chown=bun:bun schemas ./schemas
COPY --chown=bun:bun scripts ./scripts
RUN mkdir -p /data && chown bun:bun /data && chmod 700 /data
USER bun
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache BUN_INSTALL_CACHE_DIR=/tmp/.bun-cache NODE_ENV=production PRAXIS_DATA_DIR=/data PORT=8787
EXPOSE 8787
CMD ["bun", "src/main.ts"]
