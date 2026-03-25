import { useState, useEffect } from 'react';
import io from 'socket.io-client';

const socket = io('http://localhost:5000');

function HttpAnalyzer() {
    const [csvPath, setCsvPath] = useState('data/http_capture.csv');
    const [alerts, setAlerts] = useState([]);
    const [running, setRunning] = useState(false);
    const [done, setDone] = useState(false);

    useEffect(() => {
        socket.on('http_alert', (alert) => {
            setAlerts(prev => [alert, ...prev]);
        });
        socket.on('http_analysis_done', ({ total_alerts }) => {
            setRunning(false);
            setDone(true);
        });
        return () => {
            socket.off('http_alert');
            socket.off('http_analysis_done');
        };
    }, []);

    const runAnalysis = async () => {
        setAlerts([]);
        setDone(false);
        setRunning(true);
        try {
            await fetch('http://localhost:5000/analyze-http', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csv_path: csvPath })
            });
        } catch (e) {
            setRunning(false);
            alert('Backend not reachable. Make sure python app.py is running.');
        }
    };

    return (
        <div className="dashboard-card" style={{ gridColumn: 'span 4', padding: '1.5rem' }}>
            <div className="card-header" style={{ marginBottom: '1rem' }}>
                <span className="card-title" style={{ fontSize: '1.1rem', fontWeight: 600 }}>
                    HTTP Traffic Analyzer
                </span>
                <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
                    Wireshark CSV → Suspicious IP Detector
                </span>
            </div>

            {/* Input Row */}
            <div style={{ display: 'flex', gap: '15px', marginBottom: '20px', alignItems: 'center' }}>
                <input
                    type="text"
                    value={csvPath}
                    onChange={e => setCsvPath(e.target.value)}
                    placeholder="e.g. data/http_capture.csv"
                    style={{
                        flex: 1, padding: '12px 20px',
                        background: 'rgba(15, 23, 42, 0.4)', border: '1px solid var(--glass-border)',
                        borderRadius: '12px', color: 'var(--text-main)', fontSize: '0.95rem', outline: 'none'
                    }}
                />
                <button
                    onClick={runAnalysis}
                    disabled={running}
                    style={{
                        padding: '12px 24px',
                        background: running ? 'var(--glass-bg)' : 'var(--grad-primary)',
                        color: '#fff',
                        border: 'none',
                        borderRadius: '12px', fontWeight: 600,
                        cursor: running ? 'not-allowed' : 'pointer', fontSize: '0.95rem',
                        boxShadow: running ? 'none' : '0 4px 15px rgba(37, 99, 235, 0.3)'
                    }}
                >
                    {running ? '⏳ Analyzing...' : '🔍 Analyze CSV'}
                </button>
            </div>

            {/* Instructions */}
            {alerts.length === 0 && !running && !done && (
                <div style={{
                    padding: '1rem', background: '#1e293b',
                    borderRadius: '8px', color: '#64748b', fontSize: '0.85rem'
                }}>
                    <p style={{ margin: 0 }}>
                        <strong style={{ color: '#94a3b8' }}>How to use:</strong><br />
                        1. Export Wireshark capture as CSV<br />
                        2. Place it in the backend <code style={{ color: '#60a5fa' }}>data/</code> folder<br />
                        3. Enter the file path above and click Analyze CSV
                    </p>
                </div>
            )}

            {/* Running indicator */}
            {running && (
                <div style={{ color: '#60a5fa', fontSize: '0.9rem', padding: '0.5rem 0' }}>
                    ⏳ Scanning packets... alerts will appear below in real-time.
                </div>
            )}

            {/* Done — no alerts */}
            {done && alerts.length === 0 && (
                <div style={{
                    padding: '1rem', background: 'rgba(16,185,129,0.1)',
                    border: '1px solid #059669', borderRadius: '8px',
                    color: '#34d399', fontSize: '0.9rem'
                }}>
                    ✅ Analysis complete — No suspicious IPs detected. Traffic looks normal.
                </div>
            )}

            {/* Alert Cards */}
            {alerts.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '350px', overflowY: 'auto' }}>
                    {alerts.map((alert, i) => (
                        <div key={i} style={{
                            padding: '1rem',
                            background: alert.severity === 'HIGH'
                                ? 'rgba(239,68,68,0.1)' : 'rgba(245,158,11,0.1)',
                            border: `1px solid ${alert.severity === 'HIGH' ? '#ef4444' : '#f59e0b'}`,
                            borderRadius: '8px'
                        }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <span style={{
                                    fontWeight: 700, fontSize: '1rem',
                                    color: alert.severity === 'HIGH' ? '#ef4444' : '#f59e0b'
                                }}>
                                    🚨 {alert.source_ip}
                                </span>
                                <span style={{
                                    padding: '2px 10px', borderRadius: '99px', fontSize: '0.75rem', fontWeight: 700,
                                    background: alert.severity === 'HIGH' ? '#ef4444' : '#f59e0b',
                                    color: '#fff'
                                }}>
                                    {alert.severity}
                                </span>
                            </div>
                            <div style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
                                <span>📦 {alert.packet_count} packets</span>
                                <span>💾 {(alert.total_bytes / 1024).toFixed(1)} KB</span>
                                <span>🤖 ML: {alert.ml_result}</span>
                                {alert.ports?.length > 0 && <span>🔌 Ports: {alert.ports.join(', ')}</span>}
                            </div>
                            {alert.rule_flags?.length > 0 && (
                                <ul style={{ margin: '6px 0 0 0', padding: '0 0 0 1.2rem', color: '#fbbf24', fontSize: '0.82rem' }}>
                                    {alert.rule_flags.map((f, j) => <li key={j}>{f}</li>)}
                                </ul>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default HttpAnalyzer;
