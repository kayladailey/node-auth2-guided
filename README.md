# Web Auth III Guided Project


## Completion Steps
- `npm i` to download dependencies.
-  `npm run server` to start the API.
-   npm add  jsonwebtoken


//Server.js
- Add jwt library to server file
- Add /tokem endpoint 
- In the token endpoint add payload and options objects and the secret 
*Check in Postman* 
Should return a token
*check token in jwt.io*


//Auth-router.js
- Add jwt library to auth route file 
- //token function. We are adding teh token but doing so in the form of a seperate function (to keep DRY). When the client makes a request and it has the token we can verify who they are and what they are able to do.

//config - secrets.js
- We want to keep our secrets in a seperate file



// TO-DO
- Review try catch error handling 