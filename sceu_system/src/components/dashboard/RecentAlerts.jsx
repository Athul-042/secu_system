import { useState } from 'react';

function RecentAlerts({ alerts = [] }) {
    const [refreshing, setRefreshing] = useState(false);

    const defaultAlerts = [
        { title: "Inbound Attack Prevented", desc: "Brute force attempt from Seoul, KR.", type: "critical", time: "2m ago" },
        { title: "Weak Wi-Fi Detected", desc: "Current network lacks WPA3 encryption.", type: "warning", time: "1h ago" },
        { title: "Security DB Updated", desc: "Definitions v2.41 installed.", type: "info", time: "4h ago" },
    ];

    const displayAlerts = alerts.length > 0 ? alerts : defaultAlerts;

    const handleRefresh = () => {
        setRefreshing(true);
        setTimeout(() => setRefreshing(false), 1000);
    };

    return (
        <div className="dashboard-card">
            <div className="card-header">
                <span className="card-title">
                    Intelligence Feed
                    {alerts.length > 0 && (
                        <span style={{
                            marginLeft: '8px',
                            background: '#ef4444',
                            color: '#fff',
                            borderRadius: '12px',
                            padding: '1px 8px',
                            fontSize: '0.7rem',
                            fontWeight: '700'
                        }}>
                            {alerts.length}
                        </span>
                    )}
                </span>
                <span
                    onClick={handleRefresh}
                    style={{
                        fontSize: '0.8rem',
                        color: refreshing ? '#64748b' : '#3b82f6',
                        cursor: refreshing ? 'default' : 'pointer',
                        transition: 'color 0.2s'
                    }}
                >
                    {refreshing ? 'Refreshing...' : 'Refresh'}
                </span>
            </div>

            <ul className="alerts-list" style={{ maxHeight: '300px', overflowY: 'auto', paddingRight: '4px' }}>
                {displayAlerts.map((alert, index) => (
                    <li key={index} className="alert-item">
                        <div className={`alert-icon ${alert.type}`}>
                            {alert.type === 'critical' ? '!' : alert.type === 'warning' ? '⚠' : 'i'}
                        </div>
                        <div className="alert-content">
                            <h4 className="alert-title">{alert.title}</h4>
                            <p className="alert-desc">{alert.desc}</p>
                            <div className="alert-time">{alert.time}</div>
                        </div>
                    </li>
                ))}
            </ul>
        </div>
    );
}

export default RecentAlerts;
