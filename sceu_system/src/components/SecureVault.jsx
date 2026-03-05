import React, { useState, useEffect } from 'react';
import { useData } from '../contexts/DataContext';
import { simulateEncrypt, simulateDecrypt, simulateHash, MOCK_DATA } from '../utils/cryptoUtils';
import './SecureVault.css';

const SecureVault = () => {
    const { setSimulatedThreats } = useData();
    const [status, setStatus] = useState('IDLE'); // IDLE, VERIFYING, GRANTED, DENIED
    const [trustScore, setTrustScore] = useState(null);
    const [encryptedData, setEncryptedData] = useState('');
    const [displayData, setDisplayData] = useState('');
    const [logs, setLogs] = useState([]);

    useEffect(() => {
        // Initialize with encrypted data
        const init = async () => {
            const enc = simulateEncrypt(MOCK_DATA);
            setEncryptedData(enc);
            setDisplayData(enc);
            addLog("System initialized. Data locked with AES-256 simulation.");
        };
        init();
    }, []);

    const addLog = (msg) => {
        setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
    };

    const handleSimulation = async (type) => {
        setStatus('VERIFYING');
        setTrustScore(null);
        setDisplayData(encryptedData);
        addLog(`Incoming request initiated. Type: ${type === 'GOOD' ? 'Trusted Partner' : 'Suspicious Origin'}`);

        // Simulate network/processing delay
        setTimeout(async () => {
            if (type === 'GOOD') {
                const score = 95;
                setTrustScore(score);
                if (score > 80) {
                    setStatus('GRANTED');
                    addLog(`Trust Score: ${score}/100. Verification PASSED.`);
                    addLog("Decryption Key Released to client.");
                    const decrypted = simulateDecrypt(encryptedData);
                    setDisplayData(decrypted);
                }
            } else {
                const score = 25;
                setTrustScore(score);
                setStatus('DENIED');
                addLog(`Trust Score: ${score}/100. Verification FAILED.`);
                addLog("IDS Alert: Malicious pattern detected. Key request DENIED.");
                addLog("Turning hashed garbage data to requester.");

                // Triggers persistent global alert via DataContext
                setSimulatedThreats(prev => [
                    {
                        id: Date.now(),
                        source: '192.168.X.X (Simulated)',
                        type: 'critical',
                        timestamp: new Date().toISOString()
                    },
                    ...prev
                ]);

                // Show hash instead of encrypted data to simulate "garbage"
                const hash = await simulateHash(encryptedData);
                setDisplayData(`HASH: ${hash}`);
            }
        }, 2000);
    };

    const reset = () => {
        setStatus('IDLE');
        setTrustScore(null);
        setDisplayData(encryptedData);
        setLogs([]);
        addLog("System reset. Ready for new requests.");
    };

    // Initial State
    const [consensusActive, setConsensusActive] = useState(false);
    const [adminVotes, setAdminVotes] = useState({ admin1: false, admin2: false, admin3: false });

    const startRecovery = () => {
        setConsensusActive(true);
        addLog("Initiating Multi-Party Consensus Protocol (US Patent 8316237B1)...");
        addLog("Waiting for authorization from 2/3 Security Admins.");
    };

    const castVote = (admin) => {
        if (!consensusActive) return;

        setAdminVotes(prev => {
            const newVotes = { ...prev, [admin]: true };
            const yesCount = Object.values(newVotes).filter(v => v).length;

            addLog(`Admin Node ${admin.replace('admin', '')} authorized key release.`);

            if (yesCount >= 2) {
                setTimeout(() => {
                    addLog("✅ CONSENSUS REACHED (Threshold 2/3).");
                    addLog("Executing Proxy Re-Encryption...");
                    reset(); // Unlock the vault
                    setConsensusActive(false);
                    setAdminVotes({ admin1: false, admin2: false, admin3: false });
                }, 1000);
            }
            return newVotes;
        });
    };

    return (
        <div className="secure-vault-container">
            <div className="vault-header">
                <h1>🔐 Intrusion-Aware Secure Vault</h1>
                <p>Demonstration of Trust-Based Key Release & Consensus Recovery</p>
                <p className="patent-ref">Implements US Patent 8316237B1 (Secure Key Management)</p>
            </div>

            <div className="vault-grid">
                {/* Control Panel */}
                <div className="vault-card control-panel">
                    <h2>Simulation Controls</h2>

                    {/* Normal Operation Controls */}
                    {!consensusActive && (
                        <div className="control-buttons">
                            <button
                                className="btn-trusted"
                                onClick={() => handleSimulation('GOOD')}
                                disabled={status === 'VERIFYING' || status === 'DENIED'}
                            >
                                Simulate Trusted Access
                            </button>
                            <button
                                className="btn-malicious"
                                onClick={() => handleSimulation('BAD')}
                                disabled={status === 'VERIFYING'}
                            >
                                Simulate Malicious Attack
                            </button>

                            {/* Recovery Button (Only visible if Locked) */}
                            {status === 'DENIED' && (
                                <button className="btn-recovery" onClick={startRecovery}>
                                    ⚠ Initiate Consensus Recovery
                                </button>
                            )}

                            {/* Reset Button (Only visible if not Locked, for convenience) */}
                            {status !== 'DENIED' && (
                                <button className="btn-reset" onClick={reset}>Reset System</button>
                            )}
                        </div>
                    )}

                    {/* Consensus Voting Panel */}
                    {consensusActive && (
                        <div className="consensus-panel">
                            <h3>🗳️ Admin Consensus Required</h3>
                            <div className="admin-grid">
                                <button
                                    className={`btn-vote ${adminVotes.admin1 ? 'voted' : ''}`}
                                    onClick={() => castVote('admin1')}
                                    disabled={adminVotes.admin1}
                                >
                                    👤 Admin A {adminVotes.admin1 ? '✅' : 'Wait'}
                                </button>
                                <button
                                    className={`btn-vote ${adminVotes.admin2 ? 'voted' : ''}`}
                                    onClick={() => castVote('admin2')}
                                    disabled={adminVotes.admin2}
                                >
                                    👤 Admin B {adminVotes.admin2 ? '✅' : 'Wait'}
                                </button>
                                <button
                                    className={`btn-vote ${adminVotes.admin3 ? 'voted' : ''}`}
                                    onClick={() => castVote('admin3')}
                                    disabled={adminVotes.admin3}
                                >
                                    👤 Admin C {adminVotes.admin3 ? '✅' : 'Wait'}
                                </button>
                            </div>
                            <p className="consensus-status">
                                Votes: {Object.values(adminVotes).filter(v => v).length} / 3
                            </p>
                        </div>
                    )}

                    <div className="status-display">
                        <div className={`status-badge ${status.toLowerCase()}`}>
                            Status: {status}
                        </div>
                        {trustScore !== null && (
                            <div className="trust-score">
                                Trust Score: <span className={trustScore > 80 ? 'score-high' : 'score-low'}>{trustScore}</span>
                            </div>
                        )}
                    </div>
                </div>

                {/* Data View */}
                <div className="vault-card data-view">
                    <h2>Data Terminals</h2>

                    <div className="terminal-group">
                        <div className="terminal-label">Server Storage (Always Locked)</div>
                        <div className="terminal-screen locked">
                            {encryptedData.substring(0, 50)}...
                        </div>
                    </div>

                    <div className="terminal-group">
                        <div className="terminal-label">Client View (Requester)</div>
                        <div className={`terminal-screen client-view ${status === 'GRANTED' ? 'unlocked' : 'locked'}`}>
                            {displayData}
                        </div>
                    </div>
                </div>
            </div>

            {/* IDS Logs */}
            <div className="vault-card logs-panel">
                <h2>IDS Audit Logs</h2>
                <div className="logs-container">
                    {logs.map((log, i) => (
                        <div key={i} className="log-entry">{log}</div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default SecureVault;
