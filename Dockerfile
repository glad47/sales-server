FROM node:18

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# # Set production mode
# ENV NODE_ENV=production

EXPOSE 8888

CMD ["sh", "-c", "node server.js"]
