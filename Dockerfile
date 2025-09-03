# Use Node.js base image
FROM node:18

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the server code
COPY . .

# Expose the port your server runs on
EXPOSE 8888

# Start the server
CMD ["node", "server.js"]
