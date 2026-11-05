# Lab Assignment 4 — Password Authentication

## Requirements
- Java JDK 8 or newer 

## Compile and run

```bash
javac PasswordAuthentication.java
java PasswordAuthentication
```

## Features
- Register users and log in using a username and password.
- Store passwords using PBKDF2-HMAC-SHA-256 (210,000 iterations), a unique random 16-byte salt, and a 256-bit derived hash.
- Lock an account for 30 seconds after three consecutive incorrect login attempts.
- Displays a generic login failure message for an unknown username or incorrect password.
- Reset a password after verifying the user's security answer. Security answers are salted and hashed too.



