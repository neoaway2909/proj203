const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./dev.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        
        db.serialize(() => {
            // Users Table
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )`, (err) => {
                if (err) console.error("Error creating users table", err);
                
                // Add default admin and user if not exists
                db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
                    if (!row) {
                        const hash = bcrypt.hashSync('admin123', 10);
                        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['admin', hash, 'admin']);
                    }
                });

                db.get("SELECT * FROM users WHERE username = 'user'", (err, row) => {
                    if (!row) {
                        const hash = bcrypt.hashSync('user123', 10);
                        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['user', hash, 'user']);
                    }
                });
            });

            // Packet History Table (aggregated per second)
            db.run(`CREATE TABLE IF NOT EXISTS packet_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_packets INTEGER,
                tcp_count INTEGER,
                udp_count INTEGER,
                http_count INTEGER,
                https_count INTEGER,
                dns_count INTEGER,
                ssh_count INTEGER,
                encrypted_count INTEGER,
                unencrypted_count INTEGER
            )`);
        });
    }
});

module.exports = db;
