DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS comments;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    image_url TEXT
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert sample users (password: 'password')
INSERT INTO users (username, password, email, is_admin) 
VALUES ('admin', 'password', 'admin@example.com', 1);
INSERT INTO users (username, password, email, is_admin) 
VALUES ('user1', 'password', 'user1@example.com', 0);

-- Insert sample products
INSERT INTO products (name, description, price, image_url) 
VALUES ('Smartphone', 'Un smartphone de dernière génération', 499.99, 'phone.jpg');
INSERT INTO products (name, description, price, image_url) 
VALUES ('Laptop', 'Un ordinateur portable puissant', 999.99, 'laptop.jpg');
INSERT INTO products (name, description, price, image_url) 
VALUES ('Casque audio', 'Un casque audio de qualité supérieure', 149.99, 'headphones.jpg');