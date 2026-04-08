const EventEmitter = require('events');

class PacketGenerator extends EventEmitter {
    constructor(ratePerSecond = 5000) {
        super();
        this.ratePerSecond = ratePerSecond;
        this.interval = null;
        this.running = false;
        
        this.protocols = [
            { name: 'TCP', encryptedProb: 0.1 },
            { name: 'UDP', encryptedProb: 0.05 },
            { name: 'HTTP', encryptedProb: 0 },
            { name: 'HTTPS', encryptedProb: 1.0 }, // TLS 1.2, 1.3
            { name: 'DNS', encryptedProb: 0 },
            { name: 'SSH', encryptedProb: 1.0 }
        ];

        this.encryptions = ['TLS 1.2', 'TLS 1.3', 'SSL 3.0'];
    }

    start() {
        if (this.running) return;
        this.running = true;

        const updateIntervalMs = 100; // Generate batch every 100ms

        this.interval = setInterval(() => {
            const batchSize = Math.floor(this.ratePerSecond / (1000 / updateIntervalMs));
            
            const batch = [];
            const aggregate = {
                timestamp: Date.now(),
                total: batchSize,
                protocols: { TCP: 0, UDP: 0, HTTP: 0, HTTPS: 0, DNS: 0, SSH: 0 },
                encryption: { encrypted: 0, unencrypted: 0 },
                encryptionTypes: { 'TLS 1.2': 0, 'TLS 1.3': 0, 'SSL 3.0': 0 }
            };

            // Probability to sample a packet: 0.2% (0.002)
            // 1000 p/s * 0.002 = 2 rows per sec (Slow)
            // 10000 p/s * 0.002 = 20 rows per sec (Fast)

            for (let i = 0; i < batchSize; i++) {
                // Randomly select protocol
                // Distribution: heavier on HTTPS and TCP
                const rand = Math.random();
                let protocolSelect;
                if (rand < 0.4) protocolSelect = this.protocols[3]; // HTTPS
                else if (rand < 0.7) protocolSelect = this.protocols[0]; // TCP
                else if (rand < 0.8) protocolSelect = this.protocols[4]; // DNS
                else if (rand < 0.9) protocolSelect = this.protocols[1]; // UDP
                else if (rand < 0.95) protocolSelect = this.protocols[2]; // HTTP
                else protocolSelect = this.protocols[5]; // SSH

                const isEncrypted = Math.random() < protocolSelect.encryptedProb;

                let encType = null;
                if (isEncrypted) {
                    // Bias towards modern TLS
                    const erand = Math.random();
                    if (erand < 0.6) encType = 'TLS 1.3';
                    else if (erand < 0.95) encType = 'TLS 1.2';
                    else encType = 'SSL 3.0'; // deprecated but detected
                }

                // Randomly sample packets for live viewing (creates visual difference when slider changes, but keeps it readable)
                if (Math.random() < 0.002) {
                    batch.push({
                        id: Math.random().toString(36).substring(7),
                        src: `192.168.1.${Math.floor(Math.random() * 255)}`,
                        dest: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                        protocol: protocolSelect.name,
                        size: Math.floor(Math.random() * 1500) + 40,
                        isEncrypted,
                        encryptionType: encType,
                        timestamp: Date.now()
                    });
                }

                aggregate.protocols[protocolSelect.name]++;
                if (isEncrypted) {
                    aggregate.encryption.encrypted++;
                    aggregate.encryptionTypes[encType]++;
                } else {
                    aggregate.encryption.unencrypted++;
                }
            }

            this.emit('batch', { aggregate, samples: batch });

        }, updateIntervalMs);
    }

    setRate(rate) {
        this.ratePerSecond = rate;
    }

    stop() {
        if (this.interval) clearInterval(this.interval);
        this.running = false;
    }
}

module.exports = PacketGenerator;
