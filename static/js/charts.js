/**
 * Chart.js Configuration and Rendering
 * Creates all 6 charts for One_Blink dashboard
 */

// Chart.js default configuration
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.color = '#6b7280';
Chart.defaults.plugins.legend.display = true;
Chart.defaults.plugins.legend.position = 'bottom';

// Brand colors
const colors = {
    primary: '#667eea',
    secondary: '#764ba2',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#3b82f6',
    purple: '#8b5cf6',
    gradient: null
};

// Create gradient helper
function createGradient(ctx, color1, color2) {
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, color1);
    gradient.addColorStop(1, color2);
    return gradient;
}

/**
 * Chart 1: Traffic Volume Over Time (Line Chart)
 */
function createTrafficVolumeChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Traffic Volume (MB)',
                data: data.volumes,
                borderColor: colors.primary,
                backgroundColor: createGradient(ctx, 'rgba(102, 126, 234, 0.2)', 'rgba(102, 126, 234, 0)'),
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14 },
                    bodyFont: { size: 13 }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

/**
 * Chart 2: Protocol Distribution (Doughnut Chart)
 */
function createProtocolDistributionChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.protocols,
            datasets: [{
                data: data.counts,
                backgroundColor: [
                    colors.primary,
                    colors.secondary,
                    colors.purple,
                    colors.info,
                    colors.success
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Chart 3: Risk Timeline (Bar Chart)
 */
function createRiskTimelineChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.time_buckets,
            datasets: [{
                label: 'High Risk',
                data: data.high_risk,
                backgroundColor: colors.danger,
                borderRadius: 8
            }, {
                label: 'Suspicious',
                data: data.suspicious,
                backgroundColor: colors.warning,
                borderRadius: 8
            }, {
                label: 'Normal',
                data: data.normal,
                backgroundColor: colors.success,
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    stacked: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    stacked: true,
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

/**
 * Chart 4: Top Talkers (Horizontal Bar Chart)
 */
function createTopTalkersChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.ips,
            datasets: [{
                label: 'Packets',
                data: data.packet_counts,
                backgroundColor: colors.primary,
                borderRadius: 8
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

/**
 * Chart 5: Connection States (Polar Area Chart)
 */
function createConnectionStatesChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    return new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: data.states,
            datasets: [{
                data: data.counts,
                backgroundColor: [
                    'rgba(102, 126, 234, 0.7)',
                    'rgba(118, 75, 162, 0.7)',
                    'rgba(139, 92, 246, 0.7)',
                    'rgba(59, 130, 246, 0.7)',
                    'rgba(16, 185, 129, 0.7)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

/**
 * Chart 6: MITRE ATT&CK Heatmap (Custom visualization)
 */
function createMitreHeatmapChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    // Use bar chart for MITRE tactics
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.tactics,
            datasets: [{
                label: 'Techniques Detected',
                data: data.technique_counts,
                backgroundColor: data.technique_counts.map(count => {
                    if (count >= 5) return colors.danger;
                    if (count >= 3) return colors.warning;
                    return colors.info;
                }),
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            return `${context.parsed.y} techniques detected`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

/**
 * Initialize all charts with data
 */
function initializeCharts(dashboardData) {
    // Chart 1: Traffic Volume
    if (dashboardData.traffic_volume) {
        createTrafficVolumeChart('trafficVolumeChart', dashboardData.traffic_volume);
    }

    // Chart 2: Protocol Distribution
    if (dashboardData.protocol_distribution) {
        createProtocolDistributionChart('protocolDistChart', dashboardData.protocol_distribution);
    }

    // Chart 3: Risk Timeline
    if (dashboardData.risk_timeline) {
        createRiskTimelineChart('riskTimelineChart', dashboardData.risk_timeline);
    }

    // Chart 4: Top Talkers
    if (dashboardData.top_talkers) {
        createTopTalkersChart('topTalkersChart', dashboardData.top_talkers);
    }

    // Chart 5: Connection States
    if (dashboardData.connection_states) {
        createConnectionStatesChart('connectionStatesChart', dashboardData.connection_states);
    }

    // Chart 6: MITRE Heatmap
    if (dashboardData.mitre_heatmap) {
        createMitreHeatmapChart('mitreHeatmapChart', dashboardData.mitre_heatmap);
    }
}

// Export for use in other scripts
window.OneBlink = window.OneBlink || {};
window.OneBlink.Charts = {
    initializeCharts,
    createTrafficVolumeChart,
    createProtocolDistributionChart,
    createRiskTimelineChart,
    createTopTalkersChart,
    createConnectionStatesChart,
    createMitreHeatmapChart
};
