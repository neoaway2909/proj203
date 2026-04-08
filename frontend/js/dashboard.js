document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    const userRaw = localStorage.getItem('user');
    const user = userRaw ? JSON.parse(userRaw) : null;

    if (user) {
        document.getElementById('role-badge').textContent = user.role.toUpperCase();
        if (user.role === 'admin') {
            document.getElementById('admin-controls').classList.remove('hidden');
        }
    }

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/login.html';
        });
    }

    // Chart.js Default styling
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.scale.grid.color = 'rgba(255, 255, 255, 0.05)';

    // 1. Throughput Chart
    const ctxThroughput = document.getElementById('throughputChart').getContext('2d');
    const throughputChart = new Chart(ctxThroughput, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'Packets/sec',
                data: Array(20).fill(0),
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false, // Turn off for real-time performance
            scales: {
                y: { beginAtZero: true, suggestedMax: 5000 },
                x: { display: false }
            },
            plugins: { legend: { display: false } }
        }
    });

    // 2. Protocols Doughnut
    const ctxProtocol = document.getElementById('protocolChart').getContext('2d');
    const protocolChart = new Chart(ctxProtocol, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: ['#3b82f6', '#8b5cf6', '#ef4444', '#10b981', '#f59e0b', '#ec4899'],
                borderWidth: 0,
                cutout: '70%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { boxWidth: 10, padding: 15 } }
            }
        }
    });

    // 3. Encryption Mixed Chart
    const ctxEnc = document.getElementById('encryptionChart').getContext('2d');
    const encryptionChart = new Chart(ctxEnc, {
        type: 'bar',
        data: {
            labels: ['TLS 1.3', 'TLS 1.2', 'SSL 3.0', 'Unencrypted'],
            datasets: [{
                label: 'Protocols',
                data: [0, 0, 0, 0],
                backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });

    // Connect to Socket.IO
    const socket = io({
        auth: { token: token }
    });

    socket.on('connect_error', (err) => {
        console.error('Socket connection error', err);
        if (err.message === 'Authentication error') {
            localStorage.removeItem('token');
            window.location.href = '/login.html';
        }
    });

    // Metrics references
    const mThroughput = document.getElementById('metric-throughput');
    const mTcp = document.getElementById('metric-tcp');
    const mEnc = document.getElementById('metric-enc');
    const mUnenc = document.getElementById('metric-unenc');
    const tbody = document.getElementById('packet-tbody');

    // Stats history for smoothing/averaging throughput calculation over 1s (10x100ms)
    let packetsInWindow = 0;
    setInterval(() => {
        // Update Throughput Chart every 1s
        const currentArr = throughputChart.data.datasets[0].data;
        currentArr.push(packetsInWindow);
        currentArr.shift();
        
        throughputChart.update();
        mThroughput.textContent = packetsInWindow.toLocaleString();
        
        packetsInWindow = 0;
    }, 1000);

    socket.on('packetData', (data) => {
        const aggr = data.aggregate;
        packetsInWindow += aggr.total;

        // Metrics calculations
        const { protocols, encryption, encryptionTypes, total } = aggr;
        
        // Protocol Chart Update (smooth update)
        protocolChart.data.datasets[0].data = [
            protocols.TCP, protocols.UDP, protocols.HTTP,
            protocols.HTTPS, protocols.DNS, protocols.SSH
        ];
        protocolChart.update();

        // Encryption Chart Update
        encryptionChart.data.datasets[0].data = [
            encryptionTypes['TLS 1.3'],
            encryptionTypes['TLS 1.2'],
            encryptionTypes['SSL 3.0'],
            encryption.unencrypted
        ];
        encryptionChart.update();

        // Top Metrics
        if (total > 0) {
            const tcpPerc = ((protocols.TCP / total) * 100).toFixed(1);
            const encPerc = ((encryption.encrypted / total) * 100).toFixed(1);
            const unencPerc = ((encryption.unencrypted / total) * 100).toFixed(1);
            
            mTcp.textContent = isNaN(tcpPerc) ? 0 : tcpPerc;
            mEnc.textContent = isNaN(encPerc) ? 0 : encPerc;
            mUnenc.textContent = isNaN(unencPerc) ? 0 : unencPerc;
        }

        // Table Update
        data.samples.forEach(packet => {
            const tr = document.createElement('tr');
            
            const time = new Date(packet.timestamp).toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 3 });
            const isEnc = packet.isEncrypted;
            const statusClass = isEnc ? 'status-secure' : 'status-unsecure';
            const statusText = isEnc ? 'ENCRYPTED' : 'CLEARTEXT';
            const detailsText = isEnc ? packet.encryptionType : packet.protocol;
            
            tr.innerHTML = `
                <td>${time}</td>
                <td>${packet.src}</td>
                <td>${packet.dest}</td>
                <td>${packet.protocol}</td>
                <td>${packet.size} B</td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td>${detailsText}</td>
            `;

            tbody.prepend(tr);
            while (tbody.children.length > 50) {
                tbody.lastChild.remove();
            }
        });
    });

    // Admin Rate Controls
    const rateSlider = document.getElementById('rateSlider');
    const rateLabel = document.getElementById('rateLabel');
    if (rateSlider) {
        rateSlider.addEventListener('input', (e) => {
            const val = e.target.value;
            rateLabel.textContent = val;
        });
        rateSlider.addEventListener('change', (e) => {
            socket.emit('setRate', parseInt(e.target.value));
        });
    }

    socket.on('rateChanged', (rate) => {
        if (rateSlider && rateLabel && user.role !== 'admin') {
           // even if not admin, maybe visually update the slider if it was shown? (it's hidden for normal users)
        } else if (rateSlider) {
           rateSlider.value = rate;
           rateLabel.textContent = rate;
        }
    });

    // History Modal Logic
    const historyBtn = document.getElementById('historyBtn');
    const closeHistoryBtn = document.getElementById('closeHistoryBtn');
    const historyModal = document.getElementById('historyModal');
    const historyTbody = document.getElementById('history-tbody');

    if (historyBtn) {
        historyBtn.addEventListener('click', async () => {
            historyModal.classList.remove('hidden');
            historyTbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">Loading...</td></tr>';
            try {
                const res = await fetch('/api/history', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (res.ok) {
                    const rows = await res.json();
                    if (rows.length === 0) {
                        historyTbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No history data yet. Wait 1 min.</td></tr>';
                    } else {
                        historyTbody.innerHTML = '';
                        rows.forEach(row => {
                            const timeStr = new Date(row.timestamp).toLocaleTimeString();
                            const tr = document.createElement('tr');
                            tr.innerHTML = `
                                <td>${timeStr}</td>
                                <td>${row.total_packets.toLocaleString()}</td>
                                <td class="text-green">${row.encrypted_count.toLocaleString()}</td>
                                <td class="text-red">${row.unencrypted_count.toLocaleString()}</td>
                                <td>${row.tcp_count.toLocaleString()}</td>
                                <td>${row.udp_count.toLocaleString()}</td>
                                <td>${row.https_count.toLocaleString()}</td>
                            `;
                            historyTbody.appendChild(tr);
                        });
                    }
                }
            } catch (err) {
                console.error(err);
                historyTbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: red;">Failed to load data</td></tr>';
            }
        });
    }

    if (closeHistoryBtn) {
        closeHistoryBtn.addEventListener('click', () => {
            historyModal.classList.add('hidden');
        });
    }

});
