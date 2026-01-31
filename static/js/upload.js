/**
 * Upload Page JavaScript
 * Handles file upload, drag-drop, and analysis submission
 */

// DOM Elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const fileType = document.getElementById('fileType');
const analyzeBtn = document.getElementById('analyzeBtn');
const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressStatus = document.getElementById('progressStatus');

let selectedFile = null;

// Format bytes to human readable
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Handle file selection
function handleFile(file) {
    if (!file) return;

    // Validate file type
    const validExtensions = ['.pcap', '.pcapng'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    if (!validExtensions.includes(ext)) {
        alert('Invalid file type. Please upload .pcap or .pcapng files only.');
        return;
    }

    // Validate file size (max 500MB)
    const maxSize = 500 * 1024 * 1024;
    if (file.size > maxSize) {
        alert('File too large. Maximum size is 500MB.');
        return;
    }

    selectedFile = file;

    // Update UI
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    fileType.textContent = ext;

    fileInfo.classList.add('active');
    analyzeBtn.disabled = false;
}

// Drag and drop handlers
dropZone.addEventListener('click', () => {
    fileInput.click();
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFile(files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

// Analyze button handler
analyzeBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    // Get options
    const enableZeek = document.getElementById('enableZeek').checked;
    const enableSnort = document.getElementById('enableSnort').checked;
    const enableAI = document.getElementById('enableAI').checked;

    // Disable button
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Processing...';

    // Show progress
    progressContainer.classList.add('active');

    // Create form data
    const formData = new FormData();
    formData.append('pcap', selectedFile);
    formData.append('enable_zeek', enableZeek);
    formData.append('enable_snort', enableSnort);
    formData.append('enable_ai', enableAI);

    try {
        // Simulate progress stages
        const stages = [
            { percent: 10, status: 'Uploading PCAP file...' },
            { percent: 25, status: 'Running TShark extraction...' },
            { percent: 40, status: 'Normalizing to TOON format...' },
            { percent: 60, status: 'Enriching with Zeek...' },
            { percent: 75, status: 'Running Snort IDS analysis...' },
            { percent: 90, status: 'Generating AI report...' },
            { percent: 100, status: 'Complete!' }
        ];

        for (const stage of stages) {
            await new Promise(resolve => setTimeout(resolve, 800));
            updateProgress(stage.percent, stage.status);
        }

        // Send actual request
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();

            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = `/dashboard?ticket_id=${result.ticket_id}`;
            }, 1000);
        } else {
            throw new Error('Analysis failed');
        }

    } catch (error) {
        console.error('Error:', error);
        progressStatus.textContent = 'Error: ' + error.message;
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Analyze PCAP';
    }
});

function updateProgress(percent, status) {
    progressFill.style.width = percent + '%';
    progressFill.textContent = percent + '%';
    progressStatus.textContent = status;
}
