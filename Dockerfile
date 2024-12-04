FROM node:20-bookworm

WORKDIR /app

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy source files
COPY . .

# Expose port
EXPOSE 3000

# Start Express server
CMD ["npm", "start"]

