// Store scanned IPs and their status
let scannedIPs = new Map();

// Function to toggle dropdown
function toggleDropdown(element) {
    const details = element.nextElementSibling;
    const arrow = element.querySelector('.dropdown-arrow');
   
    details.classList.toggle('show');
   
    // Update the arrow text based on the state of the dropdown
    if (details.classList.contains('show')) {
        arrow.textContent = '-'; // Change to '-' when the section is open
    } else {
        arrow.textContent = '+'; // Change to '+' when the section is closed
    }
}

// Function to update the popup UI with IP addresses
function updatePopupUI() {
    const ipListElement = document.getElementById('ip-list');
   
    if (scannedIPs.size === 0) {
        ipListElement.innerHTML = '<div class="no-ips">No IP addresses found on this page</div>';
        return;
    }
    ipListElement.innerHTML = '';
    scannedIPs.forEach((data, ip) => {
        const ipDiv = document.createElement('div');
        ipDiv.className = 'ip-item';
       
        // Calculate the threat count and total vendor count
        const flaggedVendors = data.analysisStats.malicious + data.analysisStats.suspicious;
        const totalVendors = data.analysisStats.malicious + data.analysisStats.suspicious + data.analysisStats.harmless + data.analysisStats.undetected;
        
        // Create header with IP and dropdown arrow, including threat info
        const ipHeader = document.createElement('div');
        ipHeader.className = 'ip-header';
        ipHeader.onclick = () => toggleDropdown(ipHeader);
       
        const statusDot = document.createElement('span');
        statusDot.className = `status-dot ${data.isBenign ? 'safe' : 'unsafe'}`;
        statusDot.textContent = '•';
       
        const ipText = document.createElement('span');
        ipText.textContent = `${ip} (${flaggedVendors}/${totalVendors})`; // Display the threat count and total vendor count
       
        const dropdownArrow = document.createElement('span');
        dropdownArrow.className = 'dropdown-arrow';
        dropdownArrow.textContent = '+'; // Default to '+' when the section is closed
       
        ipHeader.appendChild(statusDot);
        ipHeader.appendChild(ipText);
        ipHeader.appendChild(dropdownArrow);
       
        // Create details section
        const detailsDiv = document.createElement('div');
        detailsDiv.className = 'ip-details';
       
        // Add VirusTotal link
        const vtLink = document.createElement('div');
        vtLink.className = 'detail-line';
        vtLink.innerHTML = `<span class="detail-label">VirusTotal Link:</span> <a href="https://www.virustotal.com/api/v3/ip_addresses/${ip}" target="_blank">Click Me!</a>`;
       
        // Add tags
        const tags = document.createElement('div');
        tags.className = 'detail-line';
        tags.innerHTML = `<span class="detail-label">Tags:</span> ${data.tags.length > 0 ? data.tags.join(', ') : 'None'}`;
       
        // Add last_analysis_stats
        const analysisStats = document.createElement('div');
        analysisStats.className = 'detail-line';
        analysisStats.innerHTML = `
        <span class="detail-label">Last Analysis Stats:</span>
        <ul class="analysis-list">
            <li>Malicious: ${data.analysisStats.malicious}</li>
            <li>Suspicious: ${data.analysisStats.suspicious}</li>
            <li>Harmless: ${data.analysisStats.harmless}</li>
            <li>Undetected: ${data.analysisStats.undetected}</li>
        </ul>
        `;
        detailsDiv.appendChild(vtLink);
        detailsDiv.appendChild(tags);
        detailsDiv.appendChild(analysisStats);
       
        ipDiv.appendChild(ipHeader);
        ipDiv.appendChild(detailsDiv);
        ipListElement.appendChild(ipDiv);
    });
}

browser.runtime.onMessage.addListener((message) => {
    if (message.type === 'IP_SCANNED') {
        // Store all relevant data for each IP
        scannedIPs.set(message.ip, {
            isBenign: message.isBenign,
            tags: message.tags || [],
            analysisStats: message.analysisStats
        });
        updatePopupUI();
    }
});

// Request current IP list when popup opens
browser.tabs.query({active: true, currentWindow: true}, (tabs) => {
    browser.tabs.sendMessage(tabs[0].id, {type: 'GET_SCANNED_IPS'});
});
