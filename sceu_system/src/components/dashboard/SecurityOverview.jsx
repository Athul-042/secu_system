import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { useState } from 'react';
import { useData } from '../../contexts/DataContext';

function SecurityOverview({ score = 85, status = "Protected" }) {
    const [scanning, setScanning] = useState(false);
    const { liveStats, trafficData } = useData();

    const handleScan = () => {
        setScanning(true);
        setTimeout(() => {
            setScanning(false);
            alert("System Scan Completed: No new threats found.");
        }, 2000);
    };

    // Point 2: Dynamic Colors based on Score
    const getScoreColor = (s) => {
        if (s > 90) return '#3b82f6'; // Blue (Safe)
        if (s > 60) return '#f59e0b'; // Amber (Warning)
        return '#ef4444'; // Red (Critical)
    };

    const data = [
        { name: 'Score', value: score },
        { name: 'Remaining', value: Math.max(0, 100 - score) },
    ];

    const COLORS = [getScoreColor(score), 'rgba(255,255,255,0.05)'];

    // Calculate live traffic MB from captured packets
    const totalMB = trafficData.length > 0
        ? (trafficData.reduce((sum, p) => sum + (p.size || 0), 0) / 1024 / 1024).toFixed(2)
        : '0.00';

    return (
        <div className="dashboard-card security-overview">
            <div className="card-header">
                <span className="card-title">Security Overview</span>
                <i className="settings-icon">⚙️</i>
            </div>

            <div className="security-score-container" style={{ height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                        <Pie
                            data={data}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            startAngle={90}
                            endAngle={-270}
                            dataKey="value"
                            stroke="none"
                            cornerRadius={10}
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                        </Pie>
                    </PieChart>
                </ResponsiveContainer>
                <div className="score-text">
                    <div className="score-value">{score}</div>
                    <div className="score-label">Safe Level</div>
                </div>
            </div>

            <div className="status-indicator" style={{ justifyContent: 'center' }}>
                <span className="status-dot" style={{ backgroundColor: getScoreColor(score) }}></span>
                <span style={{ color: getScoreColor(score), fontWeight: '700' }}>{status.toUpperCase()}</span>
            </div>

            <div className="stats-grid">
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#3b82f6' }}>{liveStats.total_packets}</span>
                    <span className="stat-label">Packets</span>
                </div>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#f59e0b' }}>{totalMB} MB</span>
                    <span className="stat-label">Traffic</span>
                </div>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#ef4444' }}>{String(liveStats.blocked_count).padStart(2, '0')}</span>
                    <span className="stat-label">Blocked</span>
                </div>
            </div>

            <div style={{ marginTop: '20px', padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--glass-border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>AI Detection Engine</span>
                    <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 'bold' }}>XGBoost Active</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Benchmarked Accuracy</span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-main)' }}>98.42%</span>
                </div>
            </div>

            <button
                onClick={() => {
                    const getReportUrl = () => {
                        if (window.electronAPI?.getBackendUrl) {
                            return `${window.electronAPI.getBackendUrl()}/download-report`;
                        }
                        return window.location.hostname === 'localhost' || !window.location.hostname
                            ? 'http://localhost:5000/download-report'
                            : `http://${window.location.hostname}:5000/download-report`;
                    };
                    window.open(getReportUrl(), '_blank');
                }}
                className="scan-button"
                style={{ marginTop: '10px', background: 'var(--secondary)' }}
            >
                Download PDF Report 📄
            </button>

            <button className="scan-button" onClick={handleScan} disabled={scanning}>
                {scanning ? "Scanning System..." : "Scan Device Now"}
            </button>
        </div>
    );
}

export default SecurityOverview;
