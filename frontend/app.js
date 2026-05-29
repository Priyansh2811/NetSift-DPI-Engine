document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const loading = document.getElementById('loading');
    const dashboardContent = document.getElementById('dashboard-content');
    const searchBar = document.getElementById('search-bar');
    const protocolFilter = document.getElementById('protocol-filter');
    const exportBtn = document.getElementById('export-btn');

    let appChartInstance = null;
    let timelineChartInstance = null;
    let cachedDomainsData = []; // Live Filter aur JSON Export ke liye local cache store
    let globalResponseBackup = null;

    // Click karke file browser open karne ke liye
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));

    // Drag and Drop Effects
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-emerald-500', 'bg-emerald-500/5');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-emerald-500', 'bg-emerald-500/5');
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-emerald-500', 'bg-emerald-500/5');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    // File processing aur Backend Integration
    function handleFile(file) {
        if (!file || !file.name.endsWith('.pcap')) {
            alert('Please upload a valid .pcap file format.');
            return;
        }

        loading.classList.remove('hidden');
        dashboardContent.classList.add('hidden');
        exportBtn.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', file);

        fetch('http://localhost:5000/api/analyze', {
            method: 'POST',
            body: formData
        })
        .then(res => {
            if (!res.ok) throw new Error('C++ Subprocess execution error.');
            return res.json();
        })
        .then(data => {
            loading.classList.add('hidden');
            cachedDomainsData = data.detectedDomains; // Save in cache
            globalResponseBackup = data;
            exportBtn.classList.remove('hidden');    // Show Export Button
            renderDashboard(data);
        })
        .catch(err => {
            loading.classList.add('hidden');
            alert('Error: ' + err.message);
        });
    }

    // UI Rendering Logic
    function renderDashboard(data) {
        dashboardContent.classList.remove('hidden');

        document.getElementById('stat-packets').innerText = data.metrics.totalPackets.toLocaleString();
        document.getElementById('stat-bytes').innerText = formatBytes(data.metrics.totalBytes);
        document.getElementById('stat-tcp').innerText = data.metrics.tcpPackets.toLocaleString();
        document.getElementById('stat-udp').innerText = data.metrics.udpPackets.toLocaleString();

        // 1. Initial Populate Table
        updateTable(cachedDomainsData);

        // 2. FEATURE 3: Bandwidth Timeline Line Graph (Dynamic Simulation based on package size)
        renderTimelineChart(data.metrics.totalPackets);

        // 3. Application Distribution Doughnut Chart render karna
        const labels = data.appBreakdown.map(a => a.name);
        const counts = data.appBreakdown.map(a => a.count);

        if (appChartInstance) appChartInstance.destroy();

        const ctx = document.getElementById('appChart').getContext('2d');
        appChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: ['#34d399', '#22d3ee', '#818cf8', '#fbbf24', '#f87171', '#a78bfa', '#ec4899'],
                    borderWidth: 0
                }]
            },
            options: {
                plugins: {
                    legend: { 
                        position: 'bottom', 
                        labels: { color: '#9ca3af', font: { family: 'monospace', size: 10 } } 
                    }
                },
                cutout: '72%',
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }

    // FEATURE 2: Filter Table Core Logic
    function updateTable(filteredData) {
        const tableBody = document.getElementById('domain-table-body');
        tableBody.innerHTML = '';
        
        if (filteredData.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="2" class="text-gray-500 text-center py-4">No matching L7 domain signatures found.</td></tr>`;
            return;
        }

        filteredData.forEach(item => {
            const row = document.createElement('tr');
            row.className = "hover:bg-gray-900/30 transition";
            row.innerHTML = `
                <td class="py-3 pl-2 text-gray-300 font-medium">${item.domain}</td>
                <td class="py-3 text-right pr-2 text-emerald-400 font-semibold">
                    <span class="bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 text-xs">${item.protocol}</span>
                </td>
            `;
            tableBody.appendChild(row);
        });
    }

    // Input Listeners for Real-time Searching & Filtering
    searchBar.addEventListener('input', filterData);
    protocolFilter.addEventListener('change', filterData);

    function filterData() {
        const searchText = searchBar.value.toLowerCase();
        const selectedProtocol = protocolFilter.value;

        const filtered = cachedDomainsData.filter(item => {
            const matchesSearch = item.domain.toLowerCase().includes(searchText);
            const matchesProtocol = (selectedProtocol === 'ALL' || item.protocol === selectedProtocol);
            return matchesSearch && matchesProtocol;
        });

        updateTable(filtered);
    }

    // FEATURE 3: Line Graph Processing Layout Engine
    function renderTimelineChart(totalPackets) {
        if (timelineChartInstance) timelineChartInstance.destroy();

        // Safe time milestones simulation array mapping
        const labels = ['00:01s', '00:02s', '00:03s', '00:04s', '00:05s', '00:06s', '00:07s', '00:08s', '00:09s', '00:10s'];
        
        // Split packets sequentially across points for visualization curves
        const base = Math.floor(totalPackets / 10);
        const dataPoints = labels.map((_, index) => {
            const variance = Math.floor(Math.sin(index) * (base * 0.4));
            return Math.max(2, base + variance);
        });

        const ctx = document.getElementById('timelineChart').getContext('2d');
        timelineChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Packets/Sec (Flow Velocity)',
                    data: dataPoints,
                    borderColor: '#22d3ee',
                    backgroundColor: 'rgba(34, 211, 238, 0.05)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointHoverRadius: 5,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: '#1f2937' }, ticks: { color: '#9ca3af', font: { family: 'monospace' } } },
                    y: { grid: { color: '#1f2937' }, ticks: { color: '#9ca3af', font: { family: 'monospace' } } }
                }
            }
        });
    }

   // FEATURE 4 UPGRADE: Download Excel/CSV Structured Report Engine
    exportBtn.addEventListener('click', () => {
        if (!cachedDomainsData || cachedDomainsData.length === 0) return;

        // 1. CSV ke Headers define karo
        let csvContent = "data:text/csv;charset=utf-8,";
        csvContent += "Detected Domain / Endpoint,Layer 7 Signature Protocol\n";

        // 2. Local cache memory se data ko row-by-row Excel format mein convert karo
        cachedDomainsData.forEach(item => {
            // Agar domain mein comma ho toh safe string wrapping lagao
            const domainStr = item.domain.includes(',') ? `"${item.domain}"` : item.domain;
            const protocolStr = item.protocol.includes(',') ? `"${item.protocol}"` : item.protocol;
            csvContent += `${domainStr},${protocolStr}\n`;
        });

        // 3. Browser download trigger execution
        const encodedUri = encodeURI(csvContent);
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", encodedUri);
        
        // File ka naam format set karo
        downloadAnchor.setAttribute("download", "NetSift_DPI_Analysis_Report.csv");
        document.body.appendChild(downloadAnchor);
        
        downloadAnchor.click();
        downloadAnchor.remove();
    });
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
});