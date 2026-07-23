import { useEffect, useState, useCallback } from 'react';
import io from 'socket.io-client';
import './AlertToast.css';

const getBackendUrl = () => {
    if (window.electronAPI?.getBackendUrl) {
        return window.electronAPI.getBackendUrl();
    }
    return window.location.hostname === 'localhost' ? 'http://localhost:5000' : `http://${window.location.hostname}:5000`;
};

let globalSocket;
const getSocket = () => {
    if (!globalSocket) {
        const backendUrl = getBackendUrl();
        globalSocket = io(backendUrl, {
            reconnectionDelay: 1000,
            transports: ['websocket', 'polling']
        });
    }
    return globalSocket;
};

function AlertToast() {
    const socket = getSocket();
    const [toasts, setToasts] = useState([]);

    const addToast = useCallback((toast) => {
        const id = Date.now();
        setToasts(prev => [{ ...toast, id }, ...prev].slice(0, 5));
        // Auto-remove after 6 seconds
        setTimeout(() => {
            setToasts(prev => prev.filter(t => t.id !== id));
        }, 6000);
    }, []);

    useEffect(() => {
        const handleHighFreq = (data) => {
            addToast({
                type: data.count >= 60 ? 'critical' : data.count >= 30 ? 'warning' : 'info',
                ip: data.ip,
                count: data.count,
                label: data.label
            });
        };

        socket.on('high_freq_alert', handleHighFreq);
        return () => socket.off('high_freq_alert', handleHighFreq);
    }, [addToast]);

    if (toasts.length === 0) return null;

    return (
        <div className="toast-container">
            {toasts.map(toast => (
                <div key={toast.id} className={`toast toast-${toast.type}`}>
                    <div className="toast-icon">
                        {toast.type === 'critical' ? '🚨' : toast.type === 'warning' ? '⚠️' : '🔔'}
                    </div>
                    <div className="toast-body">
                        <div className="toast-title">
                            {toast.type === 'critical' ? 'CRITICAL: High-Frequency IP' : 
                             toast.type === 'warning' ? 'WARNING: Repeated IP Detected' : 
                             'NOTICE: Frequent IP Activity'}
                        </div>
                        <div className="toast-ip">{toast.ip}</div>
                        <div className="toast-desc">{toast.count} requests — {toast.label}</div>
                    </div>
                    <button
                        className="toast-close"
                        onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}
                    >✕</button>
                </div>
            ))}
        </div>
    );
}

export default AlertToast;
