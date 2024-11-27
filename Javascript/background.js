// Store scanned IPs and their complete data
let scannedIPsData = new Map();

const API_KEYS = [
  'API-KEY HERE',
  // 'API-KEY HERE'  If you have multiple VT accounts and want to input multiple API keys
];

let currentKeyIndex = 0;

// Function to get the current API key
function getCurrentAPIKey() {
  return API_KEYS[currentKeyIndex];
}

// Function to switch to the next API key
function switchAPIKey() {
  currentKeyIndex = (currentKeyIndex + 1) % API_KEYS.length;
}

// Function to check IP reputation using VirusTotal API
async function checkIP(ipAddress) {
  // Skip private IPs
  if (isPrivateIP(ipAddress)) {
    console.log(`Skipping private IP: ${ipAddress}`);
    return;
  }

  const url = `https://www.virustotal.com/api/v3/ip_addresses/${ipAddress}`;
 
  while (currentKeyIndex < API_KEYS.length) {
    const options = {
      method: 'GET',
      headers: {
        'accept': 'application/json',
        'x-apikey': getCurrentAPIKey()
      }
    };
   
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        if (response.status === 400) {
          console.warn(`API key failed with 400 error. Switching key...`);
          switchAPIKey();
          continue;
        }
        throw new Error(`Error: ${response.status}`);
      }
     
      const data = await response.json();

      // Extract relevant information
      const analysisStats = data?.data?.attributes?.last_analysis_stats;
      const tags = data?.data?.attributes?.tags || [];
      const reputation = data?.data?.attributes?.reputation;
      
      if (analysisStats) {
        const isBenign = (
          analysisStats.malicious === 0 &&
          analysisStats.suspicious === 0
        );
        
        // Store full VirusTotal response data
        scannedIPsData.set(ipAddress, {
          fullData: data,
          isBenign: isBenign,
          tags: tags,
          reputation: reputation,
          analysisStats: analysisStats
        });

        // Send full details to popup
        browser.runtime.sendMessage({
          type: 'IP_SCANNED',
          ip: ipAddress,
          isBenign: isBenign,
          tags: tags,
          fullData: data
        });

        displayIndicator(ipAddress, isBenign);
      } else {
        console.warn(`No analysis stats found for IP: ${ipAddress}`);
      }
      
      return;
    } catch (error) {
      console.error('Error fetching IP data:', error);
      break;
    }
  }
 
  console.error('All API keys failed.');
}

// Function to check if an IP address is private
function isPrivateIP(ipAddress) {
  const parts = ipAddress.split('.').map(part => parseInt(part, 10));
  return (
    (parts[0] === 10) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 127) ||
    (parts[0] === 169 && parts[1] === 254)
  );
}

// Regular expression to match IP addresses
const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

// Function to display a dot next to the IP address without changing IP color
function displayIndicator(ipAddress, isBenign) {
  // Create a regular expression to match the IP address as a standalone word
  const ipRegex = new RegExp(`\\b${ipAddress}\\b`, 'g');

  document.body.querySelectorAll("*").forEach((node) => {
    if (node.childNodes && node.childNodes.length === 1 && node.childNodes[0].nodeType === Node.TEXT_NODE) {
      const text = node.textContent;

      if (ipRegex.test(text)) {
        const parts = text.split(ipRegex);
        node.textContent = ''; // Clear the current text content

        parts.forEach((part, index) => {
          node.appendChild(document.createTextNode(part));

          if (index < parts.length - 1) {
            const ipSpan = document.createElement('span');
            ipSpan.textContent = ipAddress;

            const dotSpan = document.createElement('span');
            dotSpan.textContent = ' •';
            dotSpan.style.color = isBenign ? 'grey' : 'red';
            dotSpan.style.fontSize = '25px';
            dotSpan.style.marginLeft = '-2px';

            node.appendChild(ipSpan);
            node.appendChild(dotSpan);
          }
        });
      }
    }
  });
}

// Scan the page for IP addresses and check each one
function scanPageForIPs() {
  const bodyText = document.body.innerText;
  const ips = bodyText.match(ipRegex);
  if (ips) {
    const uniqueIPs = [...new Set(ips)]; // Remove duplicates
    uniqueIPs.forEach(checkIP);
  }
}

// Add message listener for popup requests
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_SCANNED_IPS') {
    // Convert Map to array of objects for messaging
    const ipsArray = Array.from(scannedIPsData.entries()).map(([ip, data]) => ({
      ip,
      isBenign: data.isBenign,
      //fullData: data.fullData,
      tags: data.tags,
      //reputation: data.reputation,
      analysisStats: data.analysisStats
    }));
    
    // Send each IP to the popup with full details
    ipsArray.forEach(({ip, isBenign, fullData, tags, reputation, analysisStats}) => {
      browser.runtime.sendMessage({
        type: 'IP_SCANNED',
        ip: ip,
        isBenign: isBenign,
        //fullData: fullData,
        tags: tags,
        //reputation: reputation,
        analysisStats: analysisStats
      });
    });
  }
});

// Start scanning for IPs on page load
scanPageForIPs();