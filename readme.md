# NodeJS Authentication API 
> Authentication API  using Nodejs && Express with all commun operations. Can be used as starter for other Nodejs app.

## EndPoints : 
1. `POST` | `/api/auth/login` : login endpoint with email and password.  
2. `POST` | `/api/auth/registre` : register endpoint with username, email, password.
3. `GET` | `/api/auth/activate/:token` : activate endpoint to activate account after registration.
4. `POST` | `/api/auth/forgot` : forgot endpoint to send an email for updating password.
5. `GET` | `/api/auth//reset/:id` : reset endpoint to verify and update the current password.
6. `GET` | `/api/auth/logout` : logout endpoint.  

## Technologies Used
1.  NodeJS
2.  Express
4.  Mongoose
5.  PassportJS
6.  JWT
7.  Nodemailer
8.  bcryptjs
9.  googleapis

## Installation

##### Clone the latest Repository

`git clone https://github.com/ankouri/Nodejs-auth-api.git`

##### Into the project directory

`cd auth` 

##### Installing NPM dependencies

`npm install`

##### Change environment variables in .envfile

`MONGO_URL` : URL to connect to MongoDB.
`SECRET_KEY`: set your own secret key for password hashing.
`SESSIONKEY`: set your own session key.
Go to `console.could.google.com` and setup an account for gmailapi, you can follow this video : ` https://www.youtube.com/watch?v=-rcRf7yswfM `.
    `OAUTH2CLIENT_ID` =  Client ID 
    `OAUTH2CLIENT_SECRET` = Client Secret
    `OAUTH2CLIENT_REDIRECT_URL` = Redirect Url
    `OAUTH2CLIENT_REFRESH_TOKEN` = Refresh Token

#### The Server should now be running at http://localhost:5000/

`npm run dev`

