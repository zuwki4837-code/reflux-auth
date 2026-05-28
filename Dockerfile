FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
RUN mkdir -p /app/data
ENV DATABASE_DIR=/app/data
EXPOSE 8080
CMD ["node", "server.js"]
