import { Link, useLocation } from 'react-router-dom';
import { useData } from '../contexts/DataContext';
import { useTheme } from '../contexts/ThemeContext';
import './Navbar.css';

function Navbar() {
    const location = useLocation();
    const { liveStats } = useData();
    const { theme, toggleTheme } = useTheme();
    const isConnected = liveStats.total_packets > 0;

    const links = [
        { to: '/dashboard',    label: '🛡️ Dashboard' },
        { to: '/traffic',      label: '📡 Traffic' },
        { to: '/secure-vault', label: '🔐 Secure Vault' },
    ];

    return (
        <nav className="navbar">
            <div className="navbar-brand">
                <span className="brand-icon">⚡</span>
                <span className="brand-name">IDS System</span>
            </div>
            <div className="navbar-links">
                {links.map(link => (
                    <Link
                        key={link.to}
                        to={link.to}
                        className={`nav-link ${location.pathname === link.to ? 'active' : ''}`}
                    >
                        {link.label}
                    </Link>
                ))}
            </div>
            <div className="navbar-status">
                {/* Security Balance Pill */}
                <div className="security-balance">
                    <span className="balance-icon">🛡️</span>
                    <div className="balance-info">
                        <span className="balance-value">5,000</span>
                        <span className="balance-label">Sec-Credits</span>
                    </div>
                </div>

                <span className={`conn-dot ${isConnected ? 'online' : 'offline'}`}></span>
                <span className="conn-label">{isConnected ? 'Backend Live' : 'Disconnected'}</span>
                {isConnected && (
                    <span className="pkt-count">{liveStats.total_packets} pkts</span>
                )}
                {/* Theme Toggle Button */}
                <button
                    onClick={toggleTheme}
                    className="theme-toggle"
                    title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
                >
                    {theme === 'dark' ? '☀️' : '🌙'}
                </button>
            </div>
        </nav>
    );
}

export default Navbar;
