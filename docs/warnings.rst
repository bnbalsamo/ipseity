Warnings/Advisories
===================

- **DO NOT RUN THIS SERVER OVER HTTP** - user passwords will be transmitted in plaintext, use HTTPS
- **DO NOT LEAVE YOUR MONGO INSTANCE ACCESSIBLE TO THE INTERNET WITHOUT AUTHENTICATION** - the mongo data is cannonical, while all passwords are stored hashed, usernames will be exposed, and passwords could be changed/users deleted.
- **DO NOT EXPOSE YOUR PRIVATE KEY** - With knowledge of the private key anyone can create valid tokens for any user.
- **DO NOT RUN THE CURRENT DOCKERFILE IN PRODUCTION** - the current dockerfile runs the API over HTTP for development/testing purposes
