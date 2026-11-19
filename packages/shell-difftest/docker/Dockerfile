# T-DIFF sandbox: runs the shell-parser differential test inside a container.
# The repo is COPIED into the image (never mounted), and the container must be started
# with --network none. The test's guard (src/guard.ts) refuses to run otherwise.
#
#   docker build -f packages/shell-difftest/docker/Dockerfile -t glassbox-tdiff .
#   docker run --rm --network none glassbox-tdiff
FROM node:24-bookworm-slim
WORKDIR /repo
COPY . .
RUN corepack enable && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 pnpm install --frozen-lockfile
ENV GLASSBOX_TDIFF_SANDBOX=docker
CMD ["pnpm", "exec", "vitest", "run", "--project", "shell-difftest"]
