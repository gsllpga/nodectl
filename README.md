docker run -d \
  --name nodectl \
  --restart unless-stopped \
  -p 18080:8080 \
  -v /opt/1panel/apps/nodectl/data:/app/data \
  ghcr.io/hobin66/nodectl:latest
