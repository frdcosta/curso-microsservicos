FROM node:latest
WORKDIR .
COPY package*.json ./
RUN yarn 
COPY . .
EXPOSE 8082
CMD ["node", "app.js"]