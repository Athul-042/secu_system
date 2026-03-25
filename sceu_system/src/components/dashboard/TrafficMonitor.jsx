import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';
import { useData } from '../../contexts/DataContext';
import { useMemo } from 'react';

function TrafficMonitor() {
    const { trafficData } = useData();

    // Process trafficData for the chart
    const data = useMemo(() => {
        if (!trafficData || trafficData.length === 0) {
            // Return placeholder data if empty
            return [
                { name: '00:00', load: 0 },
                { name: '00:05', load: 0 },
            ];
        }

        // Group by time (e.g., last 10 entries or by minute)
        return trafficData.slice(-20).map(item => ({
            name: new Date(item.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            load: item.size,
            is_anomaly: item.is_anomaly,
            attack_type: item.attack_type
        }));
    }, [trafficData]);

    // Calculate Stats
    const activeConnections = trafficData.length;
    // Calculate avg speed (size / duration) -> KB/s approx
    const lastItem = trafficData[trafficData.length - 1];
    const currentSpeed = lastItem ? (lastItem.size / (lastItem.duration || 1) * 1000 / 1024).toFixed(2) : 0;

    return (
        <div className="dashboard-card traffic-monitor">
            <div className="card-header">
                <span className="card-title">Live Traffic Monitor</span>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                    <Link to="/traffic" style={{ fontSize: '0.8rem', color: '#64748b', textDecoration: 'none' }}>View Details &rarr;</Link>
                    <span className="stat-label" style={{ color: '#10b981' }}>● Live</span>
                </div>
            </div>

            <div style={{ height: 200, width: '100%' }}>
                <ResponsiveContainer>
                    <AreaChart
                        data={data}
                        margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
                    >
                        <defs>
                            <linearGradient id="colorLoad" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.8} />
                                <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                        <XAxis dataKey="name" stroke="var(--text-muted)" tick={{ fontSize: 10 }} />
                        <YAxis stroke="var(--text-muted)" tick={{ fontSize: 10 }} />
                        <Tooltip
                            content={({ active, payload }) => {
                                if (active && payload && payload.length) {
                                    const d = payload[0].payload;
                                    return (
                                        <div style={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid var(--glass-border)', padding: '10px', borderRadius: '8px', color: 'white' }}>
                                            <p style={{ margin: 0, fontSize: '0.8rem' }}>Time: {d.name}</p>
                                            <p style={{ margin: '4px 0', fontSize: '1rem', fontWeight: 'bold' }}>Load: {d.load} bytes</p>
                                            {d.is_anomaly && (
                                                <p style={{ margin: 0, color: '#ef4444', fontWeight: '800' }}>⚠️ ATTACK: {d.attack_type}</p>
                                            )}
                                        </div>
                                    );
                                }
                                return null;
                            }}
                        />
                        <Area 
                            type="monotone" 
                            dataKey="load" 
                            stroke="var(--primary)" 
                            strokeWidth={3} 
                            fillOpacity={1} 
                            fill="url(#colorLoad)"
                            dot={(props) => {
                                const { cx, cy, payload } = props;
                                if (payload.is_anomaly) {
                                    return <circle cx={cx} cy={cy} r={6} fill="#ef4444" stroke="white" strokeWidth={2} />;
                                }
                                return null;
                            }}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>

            <div className="stats-grid" style={{ marginTop: '15px' }}>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#3b82f6' }}>{currentSpeed} KB/s</span>
                    <span className="stat-label">Throughput</span>
                </div>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#10b981' }}>{(activeConnections * 1.5).toFixed(1)} MB</span>
                    <span className="stat-label">Total Data</span>
                </div>
                <div className="stat-item">
                    <span className="stat-value" style={{ color: '#f59e0b' }}>{activeConnections}</span>
                    <span className="stat-label">Active Events</span>
                </div>
            </div>
        </div>
    );
}

export default TrafficMonitor;
