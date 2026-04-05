const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./database');
const PacketGenerator = require('./packetGenerator');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Login Endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        if (bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
            res.json({ token, user: { username: user.username, role: user.role } });
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
        }
    });
});

// Admin User Management Endpoint
app.post('/api/users', (req, res) => {
    // Basic auth check inline for simplicity
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

        const { username, password, role } = req.body;
        const hash = bcrypt.hashSync(password, 10);
        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hash, role], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, username, role });
        });
    });
});

// Fetch History Data Endpoint
app.get('/api/history', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Unauthorized' });

        // Get the latest 60 minutes of history data
        db.all("SELECT * FROM packet_history ORDER BY id DESC LIMIT 60", [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });
});

// Middleware for socket.io auth
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error('Authentication error'));
        socket.user = decoded;
        next();
    });
});

// Packet Generator setup
// const generator = new PacketGenerator(5000); // Start with 5,000 packets/sec
const LiveCapture = require('./liveCapture');
const generator = new LiveCapture(); // This will use purely REAL traffic from your Wi-Fi (en0)

// Aggregation buffers for DB storage
let dbAggr = {
    tcp: 0, udp: 0, http: 0, https: 0, dns: 0, ssh: 0, encrypted: 0, unencrypted: 0, total: 0
};

generator.on('batch', (data) => {
    // Emit to all connected clients
    io.emit('packetData', data);

    // Add to DB aggregate
    dbAggr.total += data.aggregate.total;
    dbAggr.tcp += data.aggregate.protocols.TCP || 0;
    dbAggr.udp += data.aggregate.protocols.UDP || 0;
    dbAggr.http += data.aggregate.protocols.HTTP || 0;
    dbAggr.https += data.aggregate.protocols.HTTPS || 0;
    dbAggr.dns += data.aggregate.protocols.DNS || 0;
    dbAggr.ssh += data.aggregate.protocols.SSH || 0;
    dbAggr.encrypted += data.aggregate.encryption.encrypted;
    dbAggr.unencrypted += data.aggregate.encryption.unencrypted;
});

// Store to DB every minute
setInterval(() => {
    if (dbAggr.total > 0) {
        db.run(`INSERT INTO packet_history 
            (total_packets, tcp_count, udp_count, http_count, https_count, dns_count, ssh_count, encrypted_count, unencrypted_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [dbAggr.total, dbAggr.tcp, dbAggr.udp, dbAggr.http, dbAggr.https, dbAggr.dns, dbAggr.ssh, dbAggr.encrypted, dbAggr.unencrypted]
        );
        // Reset
        dbAggr = { tcp: 0, udp: 0, http: 0, https: 0, dns: 0, ssh: 0, encrypted: 0, unencrypted: 0, total: 0 };
    }
}, 60000);

io.on('connection', (socket) => {
    console.log('Client connected:', socket.user.username);
    
    socket.on('setRate', (rate) => {
        if (socket.user.role === 'admin') {
            generator.setRate(rate);
            io.emit('rateChanged', rate);
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

generator.start();

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
