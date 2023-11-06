# flask-practice
A relatively simple website made with Flask, done for a school project.
The pages feature various forms, as well as an account creation and login function.
JavaScript is used throughout the project to add interesting animations and features, such as notifying users of appropriate password creation and a sliding gallery of pictures of my dog.

## Security Considerations
- Paramterization is used to prevent SQL injection
- CSRF tokens from FLask-WTF to prevent Cross-Site Request Forgery
- Passwords are salted and hashed

## Technologies Used
- Flask
- JavaScript
- HTML / CSS
- SQLite
