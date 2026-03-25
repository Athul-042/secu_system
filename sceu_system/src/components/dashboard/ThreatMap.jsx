import { useState, useEffect, useMemo } from 'react';
import { useData } from '../../contexts/DataContext';

function ThreatMap() {
    const { allAlerts, trafficData } = useData();
    const [recentHits, setRecentHits] = useState([]);

    // Extract unique countries and counts for the leaderboard
    const countryStats = useMemo(() => {
        const stats = {};
        // Combine alerts and recent traffic for better stats
        [...allAlerts, ...trafficData.slice(-50)].forEach(item => {
            const country = item.country || (item.source?.startsWith('192.168') ? 'Local Network' : null);
            if (country && country !== 'Unknown') {
                stats[country] = (stats[country] || 0) + 1;
            }
        });
        return Object.entries(stats)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
    }, [allAlerts, trafficData]);

    useEffect(() => {
        if (trafficData.length > 0) {
            const latest = trafficData[trafficData.length - 1];
            // Check if it has a country OR if it's a known local IP
            const countryName = latest.country && latest.country !== 'Unknown' 
                ? latest.country 
                : (latest.source?.startsWith('192.168') || latest.source === '127.0.0.1' ? 'Local Network' : null);

            if (countryName) {
                const hit = {
                    ...latest,
                    country: countryName,
                    is_anomaly: latest.is_anomaly || false,
                    display_time: new Date().toLocaleTimeString()
                };
                setRecentHits(prev => {
                    // Avoid duplicate consecutive hits from same source to keep feed clean
                    if (prev.length > 0 && prev[0].source === hit.source && prev[0].country === hit.country) return prev;
                    return [hit, ...prev].slice(0, 8);
                });
            }
        }
    }, [trafficData]);

    return (
        <div className="dashboard-card" style={{ gridColumn: 'span 4', minHeight: '400px', display: 'flex', flexDirection: 'column', gap: '20px', padding: '25px' }}>
            <div className="card-header" style={{ marginBottom: '10px' }}>
                <div>
                    <span className="card-title" style={{ fontSize: '1.4rem' }}>Geographic Threat Intelligence</span>
                    <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Identifying attack origins in real-time
                    </div>
                </div>
                <div className="status-indicator">
                    <span className="status-dot" style={{ background: 'var(--accent)' }}></span>
                    <span style={{ color: 'var(--accent)', fontWeight: '600' }}>Active Geo-Tracking</span>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '30px', flex: 1 }}>
                
                {/* 2D Map Visualization Area */}
                <div style={{ 
                    background: 'rgba(15, 23, 42, 0.4)', 
                    borderRadius: '20px', 
                    border: '1px solid var(--glass-border)',
                    position: 'relative',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    overflow: 'hidden'
                }}>
                    <svg viewBox="0 0 1000 500" style={{ width: '90%', height: 'auto', opacity: 0.6 }}>
                        <path fill="var(--glass-border)" d="M250,150 L300,100 L400,120 L450,80 L500,100 L600,80 L700,120 L800,100 L850,150 L800,250 L700,300 L600,280 L500,320 L400,280 L300,300 L250,250 Z" />
                        {/* Recursive decorative elements for a "Tech" Map feel */}
                        <circle cx="200" cy="100" r="2" fill="var(--primary)" />
                        <circle cx="800" cy="400" r="2" fill="var(--danger)" />
                        <circle cx="500" cy="250" r="3" fill="var(--accent)" />
                    </svg>
                    
                    <div style={{ position: 'absolute', bottom: '20px', left: '20px', display: 'flex', gap: '15px' }}>
                        {countryStats.map(([name, count]) => (
                            <div key={name} style={{ background: 'var(--glass-bg)', padding: '5px 12px', borderRadius: '20px', fontSize: '0.8rem', border: '1px solid var(--glass-border)' }}>
                                <span style={{ color: 'var(--primary)', fontWeight: 'bold' }}>{count}</span> {name}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Live Origin Feed */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                    <h4 style={{ fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>Live Origin Feed</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        {recentHits.length === 0 ? (
                            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', fontStyle: 'italic' }}>Waiting for geographic hits...</div>
                        ) : (
                            recentHits.map((hit, i) => (
                                <div key={i} className="glass-card" style={{ 
                                    padding: '12px 15px', 
                                    display: 'flex', 
                                    justifyContent: 'space-between', 
                                    alignItems: 'center',
                                    animation: 'slideIn 0.3s ease-out'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                        <span style={{ fontSize: '1.2rem' }}>📍</span>
                                        <div>
                                            <div style={{ fontWeight: '600', fontSize: '0.95rem' }}>{hit.country}</div>
                                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{hit.source}</div>
                                        </div>
                                    </div>
                                    <div style={{ 
                                        color: hit.is_anomaly 
                                            ? (hit.severity === 'High' ? '#ef4444' : '#f59e0b') 
                                            : '#22c55e',
                                        background: hit.is_anomaly 
                                            ? (hit.severity === 'High' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(245, 158, 11, 0.1)') 
                                            : 'rgba(34, 197, 94, 0.1)',
                                        padding: '4px 10px',
                                        borderRadius: '6px',
                                        fontSize: '0.75rem',
                                        fontWeight: '800',
                                        border: `1px solid ${hit.is_anomaly 
                                            ? (hit.severity === 'High' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)') 
                                            : 'rgba(34, 197, 94, 0.2)'}`,
                                        textTransform: 'uppercase'
                                    }}>
                                        {hit.is_anomaly ? `${hit.severity || 'MED'} RISK` : 'SAFE LOG'}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
            
            <style jsx>{`
                @keyframes slideIn {
                    from { opacity: 0; transform: translateX(20px); }
                    to { opacity: 1; transform: translateX(0); }
                }
            `}</style>
        </div>
    );
}

export default ThreatMap;
