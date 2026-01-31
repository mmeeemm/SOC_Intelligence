/**
 * Dashboard Page JavaScript
 * Handles data table, filtering, and real-time updates
 */

// Sample data for testing (will be replaced with API calls)
const sampleDashboardData = {
    traffic_volume: {
        labels: ['00:00', '01:00', '02:00', '03:00', '04:00', '05:00'],
        volumes: [12.5, 18.3, 22.1, 15.8, 28.4, 31.2]
    },
    protocol_distribution: {
        protocols: ['HTTP', 'TLS', 'DNS', 'TCP', 'Other'],
        counts: [4500, 3200, 1800, 950, 500]
    },
    risk_timeline: {
        time_buckets: ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00'],
        high_risk: [5, 3, 8, 2, 12, 6],
        suspicious: [15, 12, 20, 8, 25, 18],
        normal: [80, 95, 72, 90, 63, 76]
    },
    top_talkers: {
        ips: ['192.168.1.100', '10.0.0.50', '172.16.0.25', '192.168.1.200', '10.0.0.75'],
        packet_counts: [15420, 12350, 9870, 7540, 6230]
    },
    connection_states: {
        states: ['SF', 'S0', 'REJ', 'RSTO', 'Other'],
        counts: [8500, 2340, 1250, 890, 520]
    },
    mitre_heatmap: {
        tactics: ['Initial Access', 'Execution', 'Persistence', 'Discovery', 'Exfiltration'],
        technique_counts: [3, 5, 2, 7, 1]
    }
};

// Data table management
class DataTable {
    constructor(tableId, data) {
        this.table = document.getElementById(tableId);
        this.data = data;
        this.currentPage = 1;
        this.rowsPerPage = 50;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.filters = {};
    }

    render() {
        if (!this.table) return;

        const tbody = this.table.querySelector('tbody');
        if (!tbody) return;

        tbody.innerHTML = '';

        // Apply filters
        let filteredData = this.applyFilters();

        // Apply sorting
        if (this.sortColumn) {
            filteredData = this.sortData(filteredData);
        }

        // Pagination
        const start = (this.currentPage - 1) * this.rowsPerPage;
        const end = start + this.rowsPerPage;
        const pageData = filteredData.slice(start, end);

        // Render rows
        pageData.forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${this.formatTimestamp(row.t)}</td>
                <td>${row.si || '-'}</td>
                <td>${row.di || '-'}</td>
                <td>${row.pr}</td>
                <td>${row.zeek_service || '-'}</td>
                <td>${this.renderAlert(row)}</td>
                <td><button class="btn-sm" onclick="viewDetails(${row.id})">View</button></td>
            `;
            tbody.appendChild(tr);
        });

        // Update pagination
        this.updatePagination(filteredData.length);
    }

    formatTimestamp(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    renderAlert(row) {
        if (row.alert_msg) {
            return `<span class="badge badge-danger">${row.alert_msg}</span>`;
        }
        return '<span class="badge badge-success">Clean</span>';
    }

    applyFilters() {
        return this.data.filter(row => {
            for (const [key, value] of Object.entries(this.filters)) {
                if (value && !String(row[key]).toLowerCase().includes(value.toLowerCase())) {
                    return false;
                }
            }
            return true;
        });
    }

    sortData(data) {
        return [...data].sort((a, b) => {
            const aVal = a[this.sortColumn];
            const bVal = b[this.sortColumn];

            if (aVal === bVal) return 0;

            const comparison = aVal > bVal ? 1 : -1;
            return this.sortDirection === 'asc' ? comparison : -comparison;
        });
    }

    updatePagination(totalRows) {
        const totalPages = Math.ceil(totalRows / this.rowsPerPage);
        const paginationEl = document.getElementById('pagination');

        if (!paginationEl) return;

        paginationEl.innerHTML = `
            <button onclick="dataTable.previousPage()" ${this.currentPage === 1 ? 'disabled' : ''}>Previous</button>
            <span>Page ${this.currentPage} of ${totalPages}</span>
            <button onclick="dataTable.nextPage()" ${this.currentPage === totalPages ? 'disabled' : ''}>Next</button>
        `;
    }

    nextPage() {
        this.currentPage++;
        this.render();
    }

    previousPage() {
        this.currentPage--;
        this.render();
    }

    setFilter(column, value) {
        this.filters[column] = value;
        this.currentPage = 1;
        this.render();
    }

    sort(column) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }
        this.render();
    }
}

// View event details
function viewDetails(eventId) {
    // TODO: Fetch and display event details in modal
    console.log('View details for event:', eventId);
}

// Export data
function exportData(format) {
    if (format === 'csv') {
        exportToCSV();
    } else if (format === 'json') {
        exportToJSON();
    }
}

function exportToCSV() {
    if (!window.dataTable) return;

    const headers = ['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Service', 'Alert'];
    const rows = window.dataTable.data.map(row => [
        new Date(row.t * 1000).toISOString(),
        row.si || '',
        row.di || '',
        row.pr,
        row.zeek_service || '',
        row.alert_msg || ''
    ]);

    let csv = headers.join(',') + '\n';
    rows.forEach(row => {
        csv += row.map(cell => `"${cell}"`).join(',') + '\n';
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'toon_events.csv';
    a.click();
}

function exportToJSON() {
    if (!window.dataTable) return;

    const json = JSON.stringify(window.dataTable.data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'toon_events.json';
    a.click();
}

// Initialize dashboard
function initDashboard() {
    // Fetch data from API
    fetchDashboardData().then(data => {
        // Initialize charts
        if (window.OneBlink && window.OneBlink.Charts) {
            window.OneBlink.Charts.initializeCharts(data.charts || sampleDashboardData);
        }

        // Initialize data table
        if (data.events) {
            window.dataTable = new DataTable('eventsTable', data.events);
            window.dataTable.render();
        }

        // Update metrics
        if (data.metrics) {
            updateMetrics(data.metrics);
        }
    });
}

// Fetch dashboard data from API
async function fetchDashboardData() {
    try {
        const response = await fetch('/api/dashboard');
        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
    }

    // Return sample data for testing
    return {
        charts: sampleDashboardData,
        events: generateSampleEvents(),
        metrics: {
            total_events: 27544,
            unique_sources: 142,
            high_risk: 23,
            data_volume: '1.2 GB'
        }
    };
}

// Generate sample events for testing
function generateSampleEvents() {
    const events = [];
    const protocols = ['tcp', 'udp', 'icmp'];
    const services = ['http', 'https', 'dns', 'ssh', 'smtp'];

    for (let i = 0; i < 200; i++) {
        events.push({
            id: i + 1,
            t: Date.now() / 1000 - Math.random() * 86400,
            si: `192.168.1.${Math.floor(Math.random() * 255)}`,
            di: `10.0.0.${Math.floor(Math.random() * 255)}`,
            pr: protocols[Math.floor(Math.random() * protocols.length)],
            zeek_service: Math.random() > 0.3 ? services[Math.floor(Math.random() * services.length)] : null,
            alert_msg: Math.random() > 0.9 ? 'Suspicious traffic detected' : null
        });
    }

    return events;
}

// Update metric cards
function updateMetrics(metrics) {
    document.getElementById('totalEvents').textContent = metrics.total_events.toLocaleString();
    document.getElementById('uniqueSources').textContent = metrics.unique_sources;
    document.getElementById('highRisk').textContent = metrics.high_risk;
    document.getElementById('dataVolume').textContent = metrics.data_volume;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', initDashboard);
