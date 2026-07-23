import SecurityOverview from './SecurityOverview';
import RecentAlerts from './RecentAlerts';
import TrafficMonitor from './TrafficMonitor';
import WebsiteStatus from './WebsiteStatus';
import ThreatMap from './ThreatMap';
import AttackDistribution from './AttackDistribution';
import AdaptiveProtection from './AdaptiveProtection';
import VaultUploader from '../VaultUploader';
import Navbar from '../Navbar';
import './Dashboard.css';
import { useData } from '../../contexts/DataContext';
import { Link } from 'react-router-dom';


function Dashboard() {
    const { trafficData, allAlerts, liveStats } = useData();

    // Point 2: Dynamic Safe Level from backend
    const score = liveStats.safe_level || 100;
    const status = score > 90 ? "Device is protected" : score > 60 ? "Attention Required" : "Critical Risk";

    return (
        <div style={{ minHeight: '100vh', background: '#0f172a' }}>
            <Navbar />
            <div className="dashboard-container">

                {/* Left Column */}
                <div style={{ gridColumn: 'span 1', display: 'flex', flexDirection: 'column', gap: '20px' }} className="left-panel">
                    <SecurityOverview score={score} status={status} />
                    <VaultUploader />
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

                {/* Middle Section */}
                <div style={{ gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '20px' }} className="middle-panel">
                    <TrafficMonitor />
                    <WebsiteStatus trafficData={trafficData} />
                    <AdaptiveProtection />
                </div>


                {/* Right Column */}
                {/* Right Column */}
                <div style={{ gridColumn: 'span 1', display: 'flex', flexDirection: 'column', gap: '20px' }} className="right-panel">
                    <AttackDistribution />
                    <RecentAlerts alerts={allAlerts.map(t => ({
                        title: t.severity ? `${t.severity.toUpperCase()} ALERT` : "Anomaly Detected",
                        desc: t.desc,
                        type: t.type || "critical",
                        time: t.time || "Just now"
                    }))} />
                </div>

                {/* Full-width ThreatMap */}
                <div style={{ gridColumn: 'span 4' }}>
                    <ThreatMap />
                </div>


            </div>
        </div>
    );
}

export default Dashboard;
