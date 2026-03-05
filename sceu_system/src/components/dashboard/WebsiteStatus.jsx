import { useMemo } from 'react';

function WebsiteStatus({ trafficData = [] }) {
    // Process traffic data to group by domain
    const domainStats = useMemo(() => {
        const stats = {};

        // Add some mock data if empty to demonstrate UI
        const sourceData = trafficData.length > 0 ? trafficData : [
            { url: 'https://secure-bank.com/api', duration: 120 },
            { url: 'http://insecure-legacy.net/data', duration: 45 },
            { url: 'https://google.com/search', duration: 200 },
            { url: 'https://internal-portal.corp/login', duration: 150 }
        ];

        sourceData.forEach(item => {
            try {
                const urlObj = new URL(item.url);
                const domain = urlObj.hostname;
                const isSecure = urlObj.protocol === 'https:';

                if (!stats[domain]) {
                    stats[domain] = {
                        name: domain,
                        secureCount: 0,
                        totalCount: 0,
                        avgDuration: 0,
                        protocols: new Set()
                    };
                }

                stats[domain].totalCount++;
                if (isSecure) stats[domain].secureCount++;
                stats[domain].avgDuration += item.duration || 0;
                stats[domain].protocols.add(urlObj.protocol.replace(':', ''));
            } catch (e) {
                // Ignore invalid URLs
            }
        });

        return Object.values(stats).map(stat => {
            const confidentialityRate = Math.round((stat.secureCount / stat.totalCount) * 100);
            const integrityScore = Math.round(100 - (Math.random() * 10)); // Mock integrity
            const availabilityScore = Math.max(0, 100 - Math.round(stat.avgDuration / stat.totalCount / 10)); // Simple mock availability

            let status = "Secure";
            if (confidentialityRate < 80) status = "Risk";
            if (confidentialityRate < 50) status = "Critical";

            return {
                ...stat,
                confidentialityRate,
                integrityScore,
                availabilityScore,
                status,
                protocolList: Array.from(stat.protocols).join(', ').toUpperCase()
            };
        });
    }, [trafficData]);

    return (
        <div className="dashboard-card" style={{ gridColumn: 'span 3' }}>
            <div className="card-header">
                <span className="card-title">Server Confidentiality Ratings</span>
            </div>

            <div className="website-grid">
                {domainStats.map((site, index) => (
                    <div key={index} className="website-card">
                        <div className="website-header">
                            <span className="website-name">{site.name}</span>
                            <span className={`website-badge ${site.status.toLowerCase()}`}>{site.status}</span>
                        </div>

                        <div className="metric-row">
                            <span className="metric-label">Confidentiality</span>
                            <div className="progress-bar">
                                <div
                                    className="progress-fill"
                                    style={{
                                        width: `${site.confidentialityRate}%`,
                                        backgroundColor: site.confidentialityRate > 90 ? '#10b981' : site.confidentialityRate > 50 ? '#f59e0b' : '#ef4444'
                                    }}
                                ></div>
                            </div>
                            <span className="metric-value">{site.confidentialityRate}%</span>
                        </div>

                        <div className="metric-row">
                            <span className="metric-label">Protocol</span>
                            <span className="metric-text">{site.protocolList}</span>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default WebsiteStatus;
