DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS comments;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    wallet_address TEXT UNIQUE NOT NULL,
    balance REAL NOT NULL DEFAULT 0,
    profile_picture TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (recipient_id) REFERENCES users (id)
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    comment_text TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert some sample users
INSERT INTO users (username, password, wallet_address, balance) VALUES 
    ('alice', 'password123', '5UAQj9qLqHuWk3UyjPkJ9HEHjS4goLXjdTMgUJp1MwXE', 500.0),
    ('bob', 'bobpass', 'Gg4ffDQXQRNRQj9VQQmGX9rAzA5goDegj2krXEQqbPRA', 300.0),
    ('admin', 'admin123', 'HuZ9V7zBkZ39hALiPhpkQrwbMPiqWgh7aKkNwr6HyUQv', 1000.0);
    