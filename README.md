# SecureBank: Secure Digital Banking & Fraud Detection System

A web-enabled banking system with transaction tracking, OTP-based login and real-time fraud detection. Every transfer is scored by a rule-based fraud engine, and risky transfers are flagged or blocked while an admin dashboard shows alerts as they happen.

## Features

- **User account management:** register, log in, and get a bank account with a unique account number
- **OTP-based authentication:** two-step login (password, then a 6-digit OTP that expires in 5 minutes), followed by a JWT session
- **Fund transfer and transaction history:** send money to any other account and view your full history
- **Real-time fraud detection:** each transfer gets a 0–100 risk score, and alerts reach the admin instantly through Server-Sent Events
- **Admin monitoring dashboard:** live alerts, money moved, blocked transfers, all transactions with risk scores, and options to resolve alerts and freeze accounts

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript, ReactJS |
| Backend | Node.js, Express |
| Auth | JWT, OTP, scrypt password hashing |
| Real-time | Server-Sent Events (SSE) |
| Storage | In-memory (demo); replace with MongoDB or PostgreSQL |

## Project Structure

```
securebank/
├── server.js          # Express API, OTP auth, fraud engine, admin routes
├── package.json
└── public/
    └── index.html     # React frontend (user dashboard and admin dashboard)
```

## Getting Started

**Requirements:** [Node.js](https://nodejs.org) 18 or newer, and an internet connection (React loads from a CDN).

```bash
git clone https://github.com/sumeshkadian/securebank.git
cd securebank
npm install
npm start
```

Open http://localhost:3000 in your browser.

## Demo Guide

1. Register two customer accounts, then log in as one. The OTP is shown on screen as a "Demo code" and also printed in the server console.
2. Send money to the other account number and watch the result:

   | Transfer | Risk score | Result |
   |---|---|---|
   | ₹5,000 | 0 | Success |
   | ₹60,000 | 60 | Flagged: goes through, alert raised |
   | ₹95,000 | 75 | Blocked: money does not move |

   Between midnight and 5 AM the unusual-hour rule adds 15 points, so scores will be higher.
3. In a second browser window, log in as the admin (`admin@bank.com` / `Admin@123`) to see alerts arrive live, resolve them, and freeze accounts.

## How Fraud Detection Works

Each rule that applies adds points to the transfer's risk score (capped at 100):

| Rule | Points |
|---|---|
| High-value transfer (₹50,000 or more) | 40 |
| Amount over 3x the user's average transfer | 25 |
| 3 or more transfers within one minute | 30 |
| Large amount (₹20,000 or more) to a new payee | 20 |
| Transfer between midnight and 5 AM | 15 |
| Amount drains over 90% of the balance | 15 |

**Score 70 or more:** blocked. **Score 40–69:** allowed but flagged. **Below 40:** normal. Three wrong OTP attempts also raise an alert.

## API Reference

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| POST | `/api/register` | Public | Create an account |
| POST | `/api/login` | Public | Check password, issue OTP challenge |
| POST | `/api/verify-otp` | Public | Check OTP, issue JWT |
| GET | `/api/me` | User | Current user details |
| POST | `/api/transfer` | User | Send money (runs fraud check) |
| GET | `/api/transactions` | User | Own transaction history |
| GET | `/api/admin/overview` | Admin | Stats, users, transactions, alerts |
| POST | `/api/admin/users/:id/freeze` | Admin | Freeze or unfreeze an account |
| POST | `/api/admin/alerts/:id/resolve` | Admin | Mark an alert resolved |
| GET | `/api/admin/stream` | Admin | Live alert stream (SSE) |

## Security Notes

- Passwords are hashed with scrypt and a random salt.
- Sessions use short-lived JWTs (30 minutes), and frozen accounts are denied access.
- **Demo-only shortcuts:** the OTP is returned to the browser and the admin account is pre-seeded. For real use, send the OTP by SMS or email, remove `demoOtp`, and create admins securely.
- Data is stored in memory and resets when the server restarts.

## Future Improvements

- Persistent database (MongoDB or PostgreSQL)
- Step-up OTP for high-value transfers
- Rate limiting, `helmet` and HTTPS
- Machine-learning anomaly detection alongside the rules
- Email or SMS notifications for flagged transactions

## Author

sumesh 
