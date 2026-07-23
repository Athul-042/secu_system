import React from 'react';
import SecureVault from '../components/SecureVault';
import Navbar from '../components/Navbar';

const SecureVaultPage = () => {
    return (
        <div style={{ minHeight: '100vh', background: '#0f172a' }}>
            <Navbar />
            <div className="dashboard-container" style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <SecureVault />
            </div>
        </div>
    );
};

export default SecureVaultPage;
