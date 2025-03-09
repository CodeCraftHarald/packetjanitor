// Main JavaScript for PacketJanitor

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initTooltips();
    
    // Initialize monitoring controls
    initMonitoringControls();
    
    // Initialize educational tooltips
    initEducationalTooltips();
});

// Initialize Bootstrap tooltips
function initTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialize monitoring controls
function initMonitoringControls() {
    const startBtn = document.getElementById('startMonitoringBtn');
    const stopBtn = document.getElementById('stopMonitoringBtn');
    const statusText = document.getElementById('monitoringStatusText');
    const statusIndicator = document.querySelector('.status-indicator');
    
    // Check initial monitoring status
    checkMonitoringStatus();
    
    // Set up periodic status check
    setInterval(checkMonitoringStatus, 5000);
    
    // Start monitoring button
    if (startBtn) {
        startBtn.addEventListener('click', function() {
            fetch('/dashboard/start/', {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCookie('csrftoken')
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateMonitoringUI(true);
                }
            });
        });
    }
    
    // Stop monitoring button
    if (stopBtn) {
        stopBtn.addEventListener('click', function() {
            fetch('/dashboard/stop/', {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCookie('csrftoken')
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateMonitoringUI(false);
                }
            });
        });
    }
    
    function checkMonitoringStatus() {
        fetch('/dashboard/status/')
        .then(response => response.json())
        .then(data => {
            updateMonitoringUI(data.is_running);
        });
    }
    
    function updateMonitoringUI(isRunning) {
        if (isRunning) {
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'block';
            if (statusText) statusText.textContent = 'Active';
            if (statusIndicator) statusIndicator.style.color = '#4cd964';
        } else {
            if (startBtn) startBtn.style.display = 'block';
            if (stopBtn) stopBtn.style.display = 'none';
            if (statusText) statusText.textContent = 'Inactive';
            if (statusIndicator) statusIndicator.style.color = '#ff6b6b';
        }
    }
}

// Initialize educational tooltips
function initEducationalTooltips() {
    const educationalTerms = {
        'packet': 'A packet is a small unit of data sent over a network. Think of it like a letter in the mail system.',
        'protocol': 'A protocol is a set of rules that determines how data is transmitted over a network. Like different languages for computers to communicate.',
        'ip-address': 'An IP address is a unique identifier for a device on a network, like a home address for your computer.',
        'tcp': 'TCP (Transmission Control Protocol) ensures reliable delivery of data, like sending a package with tracking and delivery confirmation.',
        'udp': 'UDP (User Datagram Protocol) sends data quickly without guaranteeing delivery, like throwing a message in a bottle into the ocean.',
        'dns': 'DNS (Domain Name System) translates human-readable website names into IP addresses, like a phone book for the internet.',
        'http': 'HTTP (Hypertext Transfer Protocol) is used for transferring web pages, like a courier service specifically for delivering documents.',
        'https': 'HTTPS is a secure version of HTTP, like sending a document in a locked briefcase instead of an open envelope.',
        'port': 'A port is a virtual point where network connections start and end, like different doors to enter a building.',
        'firewall': 'A firewall controls what traffic is allowed in and out of a network, like a security guard checking IDs at an entrance.'
    };
    
    // Find all educational tooltip elements
    const tooltipElements = document.querySelectorAll('.educational-tooltip');
    
    tooltipElements.forEach(element => {
        const term = element.getAttribute('data-term');
        if (term && educationalTerms[term]) {
            element.setAttribute('title', educationalTerms[term]);
            new bootstrap.Tooltip(element);
        }
    });
}

// Helper function to get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Format bytes to human-readable format
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Create a chart for protocol distribution
function createProtocolChart(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    '#3399ff',
                    '#4cd964',
                    '#ffcc00',
                    '#ff9500',
                    '#ff6b6b',
                    '#5856d6',
                    '#34aadc'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e0e0e0',
                        padding: 10,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: '#1e1e1e',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            cutout: '70%'
        }
    });
}

// Create a line chart for traffic over time
function createTrafficChart(elementId, labels, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packets',
                data: data,
                borderColor: '#3399ff',
                backgroundColor: 'rgba(51, 153, 255, 0.1)',
                tension: 0.4,
                fill: true
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
                    mode: 'index',
                    intersect: false,
                    backgroundColor: '#1e1e1e',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#a0a0a0'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#a0a0a0'
                    }
                }
            }
        }
    });
} 