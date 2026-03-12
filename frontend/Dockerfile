FROM node:18-alpine

WORKDIR /app

# package.json ve package-lock.json kopyala
COPY package*.json ./

# Dependencies yükle
RUN npm install

# Tüm dosyaları kopyala
COPY . .

# Port'u expose et
EXPOSE 3000

# Start komutu
CMD ["npm", "start"]
