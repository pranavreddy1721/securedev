FROM node:22-bookworm-slim

ENV NODE_ENV=production
ENV PORT=10000
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates git \
  && python3 -m pip install --no-cache-dir --break-system-packages semgrep \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 10000

CMD ["npm", "start"]
