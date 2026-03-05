import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { useState } from 'react';

function SecurityOverview({ score = 85, status = "Protected" }) {
    const [scanning, setScanning] = useState(false);

    const handleScan = () => {
        setScanning(true);
        // Simulate scan
        setTimeout(() => {
            setScanning(false);
            alert("System Scan Completed: No new threats found.");
        }, 2000);
    };
    const data = [
        { name: 'Score', value: score },
        { name: 'Remaining', value: 100 - score },
    ];

    const COLORS = ['#3b82f6', '#1e293b']; // Blue and Dark Slate

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
                <span className="status-dot"></span>
                <span>{status}</span>
            </div>

            <div className="stats-grid">
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#3b82f6' }}>32</span>
                    <span className="stat-label">Nodes</span>
                </div>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#f59e0b' }}>450</span>
                    <span className="stat-label">Traffic MB</span>
                </div>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#ef4444' }}>02</span>
                    <span className="stat-label">Blocked</span>
                </div>
            </div>

            <button className="scan-button" onClick={handleScan} disabled={scanning}>
                {scanning ? "Scanning System..." : "Scan Device Now"}
            </button>
        </div>
    );
}

export default SecurityOverview;
