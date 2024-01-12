# Web-based-Information-Security-Tool
This is a robust, secure, web-based cryptographic tool designed to cater to a spectrum of users, from beginners to advanced. Deployed on Azure App Service, This provides an array of cryptographic services, including file encryption and decryption, secure hashing, and key generation & sharing.

Access the site here: https://mihirsteganography.azurewebsites.net/ (Note: Currently Inactive)

It leverages RSA for public/private key encryption, integrates SHA-2 for secure hashing, and employs a Diffie-Hellman (DH) variant for key generation and sharing. This tool ensures robust user authentication via standard credentials, giving administrators the flexibility to manage users.

The feature set includes options to generate passwords and keys, execute symmetric and asymmetric encryption/decryption, perform steganography on files, securely save keys and documents, and compute and compare file hashes.

It utilizes Azure SQL Database service for reliable data storage and access, handling user credentials, files and their steganography output, and guest basic details. While guests can only view users' steganography work, a table with 100 private keys is available for assigning to new users, ensuring no loss of keys upon restart.
