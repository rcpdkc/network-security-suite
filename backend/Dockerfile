FROM node:18-alpine

WORKDIR /app

# netcat yükle (wait-for-db.sh için)
RUN apk add --no-cache netcat-openbsd

# package.json ve package-lock.json kopyala
COPY package*.json ./

# Dependencies yükle
RUN npm install

# Tüm dosyaları kopyala
COPY . .

# wait-for-db.sh'i executable yap
RUN chmod +x wait-for-db.sh

# Port'u expose et
EXPOSE 5000

# Start komutu
CMD ["npm", "start"]
