import { useEffect, useState } from 'react';
import SecurityOverview from './SecurityOverview';
import RecentAlerts from './RecentAlerts';
import TrafficMonitor from './TrafficMonitor';
import WebsiteStatus from './WebsiteStatus';
import './Dashboard.css';
import { useData } from '../../contexts/DataContext';

import { Link } from 'react-router-dom';

function Dashboard() {
    const { trafficData, patterns, traced, allAlerts, simulatedThreats } = useData();

    // Calculate score based on patterns/anomalies (Mock logic)
    // Score drops if there are real patterns OR simulated threats
    const totalThreats = patterns.length + simulatedThreats.length;
    const score = totalThreats > 0 ? Math.max(0, 100 - (totalThreats * 20)) : 100;
    const status = score > 80 ? "Device is protected" : score > 50 ? "Attention Required" : "Critical Risk";

    return (
        <div className="dashboard-container">
            {/* Left Column Section */}
            <div style={{ gridColumn: 'span 1', display: 'flex', flexDirection: 'column', gap: '20px' }} className="left-panel">
                <SecurityOverview score={score} status={status} />
                <div className="dashboard-card" style={{ textAlign: 'center', padding: '1.5rem' }}>
                    <h3 style={{ color: '#e2e8f0', marginBottom: '1rem' }}>Secure Data Vault</h3>
                    <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginBottom: '1rem' }}>
                        Access encrypted core system data.
                    </p>
                    <Link to="/secure-vault" style={{
                        display: 'inline-block',
                        padding: '0.75rem 1.5rem',
                        background: 'rgba(16, 185, 129, 0.2)',
                        color: '#34d399',
                        border: '1px solid #059669',
                        borderRadius: '8px',
                        textDecoration: 'none',
                        fontWeight: '600',
                        fontSize: '0.9rem'
                    }}>
                        Open Vault 🔐
                    </Link>
                </div>
            </div>

            {/* Middle Section (Traffic) */}
            <div style={{ gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '20px' }} className="middle-panel">
                <TrafficMonitor />
                <WebsiteStatus trafficData={trafficData} />
            </div>

            {/* Right Column Section */}
            {/* Right Column Section */}
            <div style={{ gridColumn: 'span 1', display: 'flex', flexDirection: 'column', gap: '20px' }} className="right-panel">
                <RecentAlerts alerts={allAlerts.map(t => ({
                    title: "Anomaly Detected",
                    desc: `Source: ${t.source || 'Unknown'}`,
                    type: "critical",
                    time: "Just now"
                }))} />
            </div>

        </div>
    );
}

export default Dashboard;
