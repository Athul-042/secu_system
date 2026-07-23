import { useState, useEffect } from 'react';
import io from 'socket.io-client';

const getBackendUrl = () => {
    if (window.electronAPI?.getBackendUrl) {
        return window.electronAPI.getBackendUrl();
    }
    return window.location.hostname === 'localhost' ? 'http://localhost:5000' : `http://${window.location.hostname}:5000`;
};

function AdaptiveProtection() {
    const BACKEND_URL = getBackendUrl();
    const [vaultState, setVaultState] = useState('ACTIVE'); // ACTIVE, PROTECTED, RECOVERY MODE
    const [threatScore, setThreatScore] = useState(0.0);
    const [transformationLevel, setTransformationLevel] = useState('LOW');
    const [protectedRequests, setProtectedRequests] = useState(0);
    const [approvals, setApprovals] = useState([]);
    const [consensusActive, setConsensusActive] = useState(false);
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(false);
    const [socket, setSocket] = useState(null);

    const fetchStatus = async () => {
        try {
            const res = await fetch(`${BACKEND_URL}/vault/status`);
            if (res.ok) {
                const data = await res.json();
                setVaultState(data.state || 'ACTIVE');
                setApprovals(data.approvals || []);
                setProtectedRequests(data.protected_requests || 0);
                if (data.state === 'RECOVERY MODE') {
                    setConsensusActive(true);
                } else {
                    setConsensusActive(false);
                }
            }
        } catch (err) {
            console.error('Error fetching vault status:', err);
        }
    };

    const fetchLogs = async () => {
        try {
            const res = await fetch(`${BACKEND_URL}/vault/logs`);
            if (res.ok) {
                const data = await res.json();
                setLogs(data.logs || []);
            }
        } catch (err) {
            console.error('Error fetching recovery logs:', err);
        }
    };

    useEffect(() => {
        fetchStatus();
        fetchLogs();

        const s = io(BACKEND_URL, {
            reconnectionDelay: 1000,
            reconnectionAttempts: Infinity,
            transports: ['websocket', 'polling']
        });

        s.on('connect', () => {
            s.emit('request_vault_status');
        });

        s.on('vault_status', (data) => {
            if (data.state) setVaultState(data.state);
            if (data.transformation_level) setTransformationLevel(data.transformation_level);
            if (data.threat_score !== undefined) setThreatScore(data.threat_score);
            if (data.protected_requests !== undefined) setProtectedRequests(data.protected_requests);
            if (data.approvals) setApprovals(data.approvals);
            if (data.state === 'RECOVERY MODE') {
                setConsensusActive(true);
            } else {
                setConsensusActive(false);
            }
            fetchLogs(); // Refresh logs on status changes
        });

        setSocket(s);

        return () => {
            s.disconnect();
        };
    }, []);

    const handleInitiateRecovery = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${BACKEND_URL}/vault/recover`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ admin_id: 'Super Admin', recovery_mode: 'RECOVERY MODE' })
            });
            if (res.ok) {
                setConsensusActive(true);
                setVaultState('RECOVERY MODE');
                fetchLogs();
            }
        } catch (err) {
            console.error('Error initiating recovery:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleApproveRecovery = async (adminId) => {
        try {
            const res = await fetch(`${BACKEND_URL}/vault/approve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ admin_id: adminId })
            });
            if (res.ok) {
                const data = await res.json();
                setApprovals(data.approvals || []);
                if (data.recovered) {
                    setConsensusActive(false);
                    setVaultState('ACTIVE');
                    setThreatScore(0.0);
                    setTransformationLevel('LOW');
                }
                fetchLogs();
            }
        } catch (err) {
            console.error('Error approving recovery:', err);
        }
    };

    const getStatusColor = () => {
        switch (vaultState) {
            case 'PROTECTED': return '#f59e0b';
            case 'RECOVERY MODE': return '#a855f7';
            case 'ACTIVE':
            default: return '#10b981';
        }
    };

    return (
        <div className="dashboard-card adaptive-protection" style={{ gridColumn: 'span 2' }}>
            <div className="card-header" style={{ marginBottom: '1.25rem' }}>
                <span className="card-title" style={{ fontSize: '1.15rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    🛡️ Adaptive Data Protection
                </span>
                <span style={{
                    fontSize: '0.75rem',
                    padding: '4px 10px',
                    borderRadius: '8px',
                    background: `${getStatusColor()}20`,
                    color: getStatusColor(),
                    fontWeight: 700,
                    border: `1px solid ${getStatusColor()}50`
                }}>
                    SYSTEM {vaultState}
                </span>
            </div>

            {/* Metrics Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '20px' }}>
                <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '12px', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', textAlign: 'center' }}>
                    <span style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>Threat Score</span>
                    <span style={{ fontSize: '1.25rem', fontWeight: 700, color: threatScore > 75 ? '#ef4444' : threatScore > 25 ? '#f59e0b' : '#3b82f6' }}>
                        {threatScore.toFixed(1)}%
                    </span>
                </div>
                <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '12px', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', textAlign: 'center' }}>
                    <span style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>Transformation</span>
                    <span style={{ fontSize: '1.1rem', fontWeight: 700, color: '#e2e8f0' }}>{transformationLevel}</span>
                </div>
                <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '12px', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', textAlign: 'center' }}>
                    <span style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '4px' }}>Protected Requests</span>
                    <span style={{ fontSize: '1.25rem', fontWeight: 700, color: '#10b981' }}>{protectedRequests}</span>
                </div>
            </div>

            {/* Active Protection State Description */}
            {vaultState === 'PROTECTED' && (
                <div style={{
                    padding: '12px 16px',
                    background: 'rgba(245, 158, 11, 0.1)',
                    border: '1px solid rgba(245, 158, 11, 0.2)',
                    borderRadius: '12px',
                    fontSize: '0.85rem',
                    color: '#fbbf24',
                    marginBottom: '15px',
                    lineHeight: '1.4'
                }}>
                    ⚠️ <strong>Active Defense Triggered:</strong> Outgoing sensitive responses for attackers are currently being dynamically obfuscated/encrypted. Clear-text records are only served to verified normal sessions.
                </div>
            )}

            {/* Recovery State Control Area */}
            <div style={{ marginBottom: '20px' }}>
                {!consensusActive ? (
                    <button
                        onClick={handleInitiateRecovery}
                        disabled={loading || vaultState === 'ACTIVE'}
                        style={{
                            width: '100%',
                            padding: '12px',
                            background: vaultState === 'ACTIVE' ? 'rgba(255,255,255,0.02)' : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                            color: vaultState === 'ACTIVE' ? '#475569' : '#fff',
                            border: vaultState === 'ACTIVE' ? '1px solid rgba(255,255,255,0.05)' : 'none',
                            borderRadius: '12px',
                            fontWeight: 600,
                            cursor: vaultState === 'ACTIVE' ? 'not-allowed' : 'pointer',
                            transition: 'all 0.2s ease',
                            boxShadow: vaultState === 'ACTIVE' ? 'none' : '0 4px 12px rgba(239, 68, 68, 0.2)'
                        }}
                    >
                        🔑 Initiate Recovery Mode
                    </button>
                ) : (
                    <div style={{ background: 'rgba(168, 85, 247, 0.08)', border: '1px solid rgba(168, 85, 247, 0.2)', padding: '16px', borderRadius: '16px' }}>
                        <span style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#d8b4fe', marginBottom: '8px', textAlign: 'center' }}>
                            🗳️ Dual-Admin Consensus Required (Approvals: {approvals.length}/2)
                        </span>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '10px' }}>
                            <button
                                onClick={() => handleApproveRecovery('Admin A')}
                                disabled={approvals.includes('Admin A')}
                                style={{
                                    padding: '10px',
                                    background: approvals.includes('Admin A') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255,255,255,0.05)',
                                    color: approvals.includes('Admin A') ? '#34d399' : '#e2e8f0',
                                    border: `1px solid ${approvals.includes('Admin A') ? '#10b981' : 'rgba(255,255,255,0.1)'}`,
                                    borderRadius: '10px',
                                    fontWeight: 500,
                                    cursor: approvals.includes('Admin A') ? 'not-allowed' : 'pointer'
                                }}
                            >
                                Admin A {approvals.includes('Admin A') ? '✅' : '✍️ Sign'}
                            </button>
                            <button
                                onClick={() => handleApproveRecovery('Admin B')}
                                disabled={approvals.includes('Admin B')}
                                style={{
                                    padding: '10px',
                                    background: approvals.includes('Admin B') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255,255,255,0.05)',
                                    color: approvals.includes('Admin B') ? '#34d399' : '#e2e8f0',
                                    border: `1px solid ${approvals.includes('Admin B') ? '#10b981' : 'rgba(255,255,255,0.1)'}`,
                                    borderRadius: '10px',
                                    fontWeight: 500,
                                    cursor: approvals.includes('Admin B') ? 'not-allowed' : 'pointer'
                                }}
                            >
                                Admin B {approvals.includes('Admin B') ? '✅' : '✍️ Sign'}
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* Audit Logs */}
            <div>
                <span style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: '#94a3b8', marginBottom: '8px' }}>
                    Recovery Audit Logs
                </span>
                <div style={{
                    maxHeight: '120px',
                    overflowY: 'auto',
                    background: '#090d16',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                    borderRadius: '10px',
                    padding: '10px',
                    fontFamily: 'monospace',
                    fontSize: '0.75rem'
                }}>
                    {logs.length === 0 ? (
                        <div style={{ color: '#475569', fontStyle: 'italic' }}>No audit trail registered.</div>
                    ) : (
                        logs.slice().reverse().map((log, i) => (
                            <div key={i} style={{
                                color: log.includes('Dual-Admin') || log.includes('restored') ? '#34d399' : log.includes('Shield') ? '#f59e0b' : '#94a3b8',
                                marginBottom: '4px',
                                borderBottom: '1px solid rgba(255,255,255,0.02)',
                                paddingBottom: '2px'
                            }}>
                                {log}
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}

export default AdaptiveProtection;
