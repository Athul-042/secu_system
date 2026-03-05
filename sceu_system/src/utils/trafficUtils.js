// Utility functions for traffic analysis

export function extractFeatures(trafficData) {
  return trafficData.map(item => ({
    url: item.destination, // Mapping dest IP to URL for compatibility
    responseTime: 0, // Not available in simple packet capture
    requestSize: item.size,
    source: item.source,
    protocol: item.protocol,
    // Pass through backend ML results
    isBackendAnomaly: item.is_anomaly,
    confidence: item.confidence,
    action: item.action
  }));
}

// Basic stats: Counts per protocol, total bytes, avg size
export function calculateStatistics(trafficData) {
  const stats = {
    totalBytes: 0,
    protocolCounts: { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
    packetCount: trafficData.length,
  };

  trafficData.forEach(packet => {
    stats.totalBytes += packet.size;
    const proto = packet.protocol || 'OTHER';
    stats.protocolCounts[proto] = (stats.protocolCounts[proto] || 0) + 1;
  });

  return stats;
}

export function detectAnomalies(packet) {
  const anomalies = [];

  // Rule 0: Backend ML Model Detection
  if (packet.isBackendAnomaly) {
    if (packet.action === 'BLOCKED') {
      anomalies.push(`⛔ ACCESS BLOCKED: Firewall rule added for ${packet.source}`);
    } else if (packet.confidence > 99) {
      anomalies.push(`CRITICAL: AI Model Flagged Attack (Conf: ${packet.confidence}%)`);
    } else {
      anomalies.push(`Suspicious Background Activity / Tracking (Conf: ${packet.confidence}%)`);
    }
  }

  // Rule 1: Large Packet (Potential Buffer Overflow / Exfiltration)
  if (packet.size > 1500 && packet.protocol !== 'TCP') {
    anomalies.push('Abnormal Packet Size (>1500 bytes)');
  }

  // Rule 2: Restricted/Suspicious Ports (Mock logic as we don't have ports yet in Python sniffer, 
  // but we can add logic for future)

  // Rule 3: Protocol Check (Example: ICMP flood warning if too many ICMP)
  if (packet.protocol === 'ICMP') {
    anomalies.push('ICMP Packet Detected (Potential Scanning)');
  }

  return anomalies;
}

export function traceSource(patterns) {
  return patterns.map(pattern => ({
    sourceIP: pattern.source || 'Unknown',
    timestamp: pattern.timestamp,
    reason: pattern.anomalies.join(', '),
    url: pattern.url,
  }));
}
