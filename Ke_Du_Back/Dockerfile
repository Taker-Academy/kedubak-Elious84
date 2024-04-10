FROM node:16
WORKDIR /server
COPY package*.json ./
RUN npm install
RUN npm i axios
RUN npm i bcrypt
RUN npm i cors
RUN npm i dotenv
RUN npm i express
RUN npm i jsonwebtoken
RUN npm i mongodb
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]