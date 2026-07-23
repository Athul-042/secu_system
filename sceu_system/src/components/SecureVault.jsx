import React, { useState, useEffect } from 'react';
import { useData } from '../contexts/DataContext';
import io from 'socket.io-client';
import './SecureVault.css';

const getBackendUrl = () => {
    if (window.electronAPI?.getBackendUrl) {
        return window.electronAPI.getBackendUrl();
    }
    return window.location.hostname === 'localhost' ? 'http://localhost:5000' : `http://${window.location.hostname}:5000`;
};

const SecureVault = () => {
    const BACKEND_URL = getBackendUrl();
    const { setSimulatedThreats } = useData();
    const [vaultState, setVaultState] = useState('ACTIVE'); // ACTIVE, PROTECTED, RECOVERY MODE
    const [approvals, setApprovals] = useState([]);
    const [publicRecords, setPublicRecords] = useState([]);
    const [originalRecords, setOriginalRecords] = useState([]);
    const [consensusActive, setConsensusActive] = useState(false);
    const [logs, setLogs] = useState([]);
    const [vaultLogs, setVaultLogs] = useState([]);
    const [loading, setLoading] = useState(false);

    const addLog = (msg) => {
        setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
    };

    const fetchVaultStatus = async () => {
        try {
            const res = await fetch(`${BACKEND_URL}/vault/status`);
            if (res.ok) {
                const data = await res.json();
                setVaultState(data.state);
                setApprovals(data.approvals);
                setPublicRecords(data.public_records);
                setOriginalRecords(data.original_records);
            }
        } catch (err) {
            console.error("Error fetching vault status:", err);
            addLog("⚠️ Error connecting to vault backend.");
        }
    };

    const fetchVaultLogs = async () => {
        try {
            const res = await fetch(`${BACKEND_URL}/vault/logs`);
            if (res.ok) {
                const data = await res.json();
                setVaultLogs(data.logs || []);
            }
        } catch (err) {
            console.error("Error fetching vault logs:", err);
            addLog("⚠️ Unable to load backend audit logs.");
        }
    };

    useEffect(() => {
        fetchVaultStatus();
        fetchVaultLogs();
        addLog("🛡️ Vault Client connected to backend.");

        const socket = io(BACKEND_URL, {
            reconnectionDelay: 1000,
            reconnectionAttempts: Infinity,
            transports: ['websocket', 'polling']
        });

        socket.on('connect', () => {
            console.log("SecureVault socket connected");
        });

        socket.on('vault_status', (data) => {
            if (data.state) {
                setVaultState(data.state);
                if (data.state === 'RECOVERY MODE') {
                    setConsensusActive(true);
                } else if (data.state === 'ACTIVE') {
                    setConsensusActive(false);
                }
            }
            if (data.approvals) setApprovals(data.approvals);
            fetchVaultStatus();
            fetchVaultLogs();
        });

        return () => {
            socket.disconnect();
        };
    }, []);


    const triggerSimulation = async (level) => {
        setLoading(true);
        addLog(`Triggering simulated threat level: ${level.toUpperCase()}`);
        try {
            const res = await fetch(`${BACKEND_URL}/vault/simulate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threat_level: level })
            });
            if (res.ok) {
                addLog(`Success: Simulated ${level} threat applied.`);
                if (level !== 'NONE') {
                    // Trigger global alert toast in dashboard context
                    setSimulatedThreats(prev => [
                        {
                            id: Date.now(),
                            source: 'IDS Active Defense Trigger',
                            type: level === 'HIGH' ? 'critical' : 'warning',
                            timestamp: new Date().toISOString()
                        },
                        ...prev
                    ]);
                }
                await fetchVaultStatus();
                await fetchVaultLogs();
            } else {
                addLog("❌ Failed to apply simulated threat.");
            }
        } catch (err) {
            addLog("❌ API Error triggering threat simulation.");
        } finally {
            setLoading(false);
        }
    };

    const handleApproveRecovery = async (adminId) => {
        addLog(`Cast Recovery Authorization: ${adminId}`);
        try {
            const res = await fetch(`${BACKEND_URL}/vault/approve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ admin_id: adminId })
            });
            if (res.ok) {
                const data = await res.json();
                setApprovals(data.approvals);
                addLog(`Admin ${adminId} approved file recovery.`);
                if (data.recovered) {
                    addLog("✅ Consensus threshold met (2/2 approvals)!");
                    addLog("Decryption key released. Restoring data to normal...");
                    setConsensusActive(false);
                    await fetchVaultStatus();
                    await fetchVaultLogs();
                } else {
                    addLog(`Waiting for 2nd Admin approval. Current approvals: ${data.approvals.join(', ')}`);
                }
            } else {
                addLog("❌ Failed to register recovery approval.");
            }
        } catch (err) {
            addLog("❌ Error approving recovery.");
        }
    };

    const startRecoveryFlow = async () => {
        addLog("Initiating Consensus Recovery Protocol (Dual Admin Sign-off Required)...");
        try {
            const res = await fetch(`${BACKEND_URL}/vault/recover`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ admin_id: 'Super Admin', recovery_mode: 'RECOVERY MODE' })
            });
            if (res.ok) {
                setConsensusActive(true);
                setVaultState('RECOVERY MODE');
                addLog("Recovery mode initiated on backend successfully.");
            }
        } catch (err) {
            console.error("Error starting recovery flow:", err);
            addLog("❌ Error initiating recovery on backend.");
        }
    };


    const renderTable = (records) => {
        if (typeof records === 'string') {
            return (
                <div className="terminal-screen locked" style={{ whiteSpace: 'pre-wrap', maxHeight: '250px', overflowY: 'auto' }}>
                    {records}
                </div>
            );
        }
        if (!Array.isArray(records) || records.length === 0) {
            return <div style={{ color: '#94a3b8', fontStyle: 'italic' }}>No records found or file empty.</div>;
        }
        return (
            <div style={{ overflowX: 'auto', maxHeight: '250px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ borderBottom: '2px solid rgba(255,255,255,0.1)', color: '#94a3b8' }}>
                            <th style={{ padding: '8px' }}>ID</th>
                            <th style={{ padding: '8px' }}>Name</th>
                            <th style={{ padding: '8px' }}>SSN</th>
                            <th style={{ padding: '8px' }}>Grade</th>
                            <th style={{ padding: '8px' }}>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {records.map((r, i) => (
                            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                <td style={{ padding: '8px', color: '#60a5fa' }}>{r.student_id}</td>
                                <td style={{ padding: '8px', fontWeight: 500 }}>{r.name}</td>
                                <td style={{ padding: '8px', fontFamily: 'monospace' }}>{r.ssn}</td>
                                <td style={{ padding: '8px', color: r.grade?.includes('*') ? '#f59e0b' : '#34d399', fontWeight: 'bold' }}>{r.grade}</td>
                                <td style={{ padding: '8px' }}>
                                    <span style={{
                                        padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem',
                                        background: r.status === 'Active' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                                        color: r.status === 'Active' ? '#34d399' : '#f87171'
                                    }}>{r.status}</span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    const getShieldColor = () => {
        switch (vaultState) {
            case 'PROTECTED': return '#f59e0b';
            case 'RECOVERY MODE': return '#a855f7';
            case 'ACTIVE':
            default: return '#10b981';
        }
    };


    return (
        <div className="secure-vault-container">
            <div className="vault-header">
                <h1>🛡️ Intrusion-Aware Active Recovery Vault</h1>
                <p>Dynamic Data Protection Levels & Dual-Admin Consensus Sign-off</p>
            </div>

            <div className="vault-grid">
                {/* Control Panel */}
                <div className="vault-card control-panel">
                    <h2>Simulation Dashboard</h2>
                    <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '20px' }}>
                        Simulate attacks to demonstrate dynamic protection levels.
                    </p>

                    {!consensusActive && (
                        <div className="control-buttons">
                            <button
                                className="btn-trusted"
                                onClick={() => triggerSimulation('NONE')}
                                disabled={loading || vaultState === 'ACTIVE'}
                                style={{ background: vaultState === 'ACTIVE' ? 'rgba(16,185,129,0.1)' : 'var(--grad-primary)' }}
                            >
                                Reset System (Normal State)
                            </button>
                            <button
                                className="btn-vote"
                                onClick={() => triggerSimulation('LOW')}
                                disabled={loading}
                                style={{ border: '1px solid #f59e0b', color: '#f59e0b' }}
                            >
                                Simulate Low-Threat (Apply Masking)
                            </button>
                            <button
                                className="btn-malicious"
                                onClick={() => triggerSimulation('MEDIUM')}
                                disabled={loading}
                            >
                                Simulate Med-Threat (AES-256 Encrypt)
                            </button>
                            <button
                                className="btn-recovery"
                                onClick={() => triggerSimulation('HIGH')}
                                disabled={loading}
                                style={{ background: 'rgba(168,85,247,0.2)', border: '1px solid #a855f7', color: '#d8b4fe' }}
                            >
                                Simulate High-Threat (Swap Decoy File)
                            </button>

                            {vaultState !== 'ACTIVE' && (

                                <button
                                    className="btn-recovery"
                                    onClick={startRecoveryFlow}
                                    style={{ marginTop: '20px', background: '#e11d48', color: '#fff', boxShadow: '0 4px 15px rgba(225, 29, 72, 0.4)' }}
                                >
                                    🔑 Initiate Consensus Recovery
                                </button>
                            )}
                        </div>
                    )}

                    {consensusActive && (
                        <div className="consensus-panel">
                            <h3>🗳️ Consensus recovery (2/2 Approvals Required)</h3>
                            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '15px' }}>
                                Recovery key release requires two independent administrator approvals.
                            </p>
                            <div className="admin-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                                <button
                                    className={`btn-vote ${approvals.includes('Admin A') ? 'voted' : ''}`}
                                    onClick={() => handleApproveRecovery('Admin A')}
                                    disabled={approvals.includes('Admin A')}
                                >
                                    👤 Admin A {approvals.includes('Admin A') ? '✅' : 'Sign Off'}
                                </button>
                                <button
                                    className={`btn-vote ${approvals.includes('Admin B') ? 'voted' : ''}`}
                                    onClick={() => handleApproveRecovery('Admin B')}
                                    disabled={approvals.includes('Admin B')}
                                >
                                    👤 Admin B {approvals.includes('Admin B') ? '✅' : 'Sign Off'}
                                </button>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '15px', alignItems: 'center' }}>
                                <button className="btn-reset" onClick={() => setConsensusActive(false)} style={{ padding: '8px 16px', fontSize: '0.8rem' }}>
                                    Cancel
                                </button>
                                <span className="consensus-status" style={{ fontSize: '0.85rem', color: '#f59e0b', fontWeight: 'bold' }}>
                                    Approvals: {approvals.length} / 2
                                </span>
                            </div>
                        </div>
                    )}

                    <div className="status-display" style={{ borderLeft: `4px solid ${getShieldColor()}`, marginTop: '25px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.9rem', color: '#94a3b8' }}>Protection Status:</span>
                            <span className="status-badge" style={{ background: getShieldColor(), color: '#fff', padding: '4px 12px', fontSize: '0.8rem' }}>
                                {vaultState}
                            </span>
                        </div>
                    </div>
                </div>

                {/* Data View */}
                <div className="vault-card data-view">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        <div>
                            <h2 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>👤 Hacker's View (Public Active File)</h2>
                            <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '10px' }}>
                                Content of <code>data/sensitive_files/student_records.csv</code>
                            </p>
                            <div className="terminal-screen client-view" style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.05)' }}>
                                {renderTable(publicRecords)}
                            </div>
                        </div>

                        <div>
                            <h2 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>🔒 Protected Vault View (Original Data)</h2>
                            <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '10px' }}>
                                Secured backup data isolated from the active environment.
                            </p>
                            <div className="terminal-screen" style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.05)' }}>
                                {renderTable(originalRecords)}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Audit Logs */}
            <div className="vault-card logs-panel">
                <h2>Active Defense Audit Log</h2>
                <div className="logs-container">
                    {logs.map((log, i) => (
                        <div key={`local-${i}`} className="log-entry" style={{ color: log.includes('❌') || log.includes('⚠️') ? '#f87171' : log.includes('✅') ? '#34d399' : '#94a3b8' }}>
                            {log}
                        </div>
                    ))}
                </div>
            </div>

            <div className="vault-card logs-panel" style={{ marginTop: '20px' }}>
                <h2>Backend Vault Audit Trail</h2>
                <div className="logs-container">
                    {vaultLogs.length === 0 ? (
                        <div style={{ color: '#94a3b8', fontStyle: 'italic' }}>No backend audit entries available.</div>
                    ) : vaultLogs.map((log, i) => (
                        <div key={`backend-${i}`} className="log-entry" style={{ color: '#e2e8f0' }}>
                            {log}
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default SecureVault;
