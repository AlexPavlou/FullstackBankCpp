<h1 align="center" style="font-size: 2em;">Banking Service API 💳</h1>

> A secure, high-performance banking backend with a modern React-based frontend.

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=flat&logo=c%2B%2B&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-%23336791.svg?style=flat&logo=postgresql&logoColor=white)
![React](https://img.shields.io/badge/react-%2361DAFB.svg?style=flat&logo=react&logoColor=white)

## Summary 📝
> This project is a robust banking system featuring:
- A **C++ backend** with Crow, PostgreSQL, and multithreading for efficiency.
- A **React frontend** with dynamic elements for seamless user experience.
- Secure authentication, encryption, and transaction management.

## Features ✨
- **Secure API**: C++ backend using Crow for high-speed, scalable API requests.
- **User Authentication**: Secure password hashing with Argon2 and encryption.
- **Account Management**: Create, manage, and view multiple accounts.
- **Transactions**: Deposit, withdraw, transfer funds with tracking.
- **Encryption & Security**: Secure database storage with PostgreSQL and encryption.
- **Multithreading**: Efficient request handling for fast responses.

## Requirements 📋

To build and run this project, the following dependencies are required:
- **C++17 or later**
- **Crow C++**: Lightweight and fast HTTP framework.
- **PostgreSQL**: Used for storing user data and transactions.
- **libsodium**: Secure password hashing and encryption.

## Installing Dependencies ⚙️

### On Ubuntu
```bash
sudo apt update
sudo apt install libsodium-dev postgresql libpq-dev
```

### On macOS
```bash
brew install libsodium postgresql
```

### On Windows
1. Download and install [PostgreSQL](https://www.postgresql.org/download/).
2. Download and install [libsodium](https://libsodium.gitbook.io/doc/installation).
3. Configure your compiler to include the necessary dependencies.

## Usage 🚀
1. Clone or download the repository.
2. Compile the backend using Meson:
   ```bash
   meson setup build
   ninja -C build
   ```
3. Start the backend:
   ```bash
   ./build/banking-service
   ```
4. Run the frontend:
   ```bash
   cd frontend
   npm install
   npm start
   ```
