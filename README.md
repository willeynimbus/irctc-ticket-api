# IRCTC-like Ticket Booking System API

This is a simple API for an IRCTC-like ticket booking system built with Node.js, Express, and PostgreSQL.

## Setup

1. Clone the repository.
2. Install dependencies: `npm install`.
3. Create a `.env` file and add your environment variables (see `.env.example`).
4. Run the server: `node index.js`.

## API Endpoints

- **POST /register**: Register a new user.
- **POST /login**: Login a user and get an access token.
- **POST /trains**: Add a new train (Admin only).
- **GET /availability**: Get seat availability between two stations.
- **POST /book**: Book a seat on a train.
- **GET /booking/:id**: Get specific booking details.

## Testing

You can use tools like Postman to test the API endpoints.
