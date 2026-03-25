import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { useMemo } from 'react';
import { useData } from '../../contexts/DataContext';

function AttackDistribution() {
    const { allAlerts } = useData();

    const data = useMemo(() => {
        const counts = {};
        allAlerts.forEach(alert => {
            const type = alert.attack_type || 'Other';
            counts[type] = (counts[type] || 0) + 1;
        });

        if (Object.keys(counts).length === 0) return [{ name: 'No Threats', value: 1 }];

        return Object.entries(counts).map(([name, value]) => ({ name, value }));
    }, [allAlerts]);

    const COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#ec4899'];

    return (
        <div className="dashboard-card" style={{ height: '300px', display: 'flex', flexDirection: 'column' }}>
            <div className="card-header">
                <span className="card-title">Attack Distribution</span>
            </div>
            <div style={{ flex: 1, width: '100%' }}>
                <ResponsiveContainer>
                    <PieChart>
                        <Pie
                            data={data}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                        </Pie>
                        <Tooltip 
                            contentStyle={{ 
                                backgroundColor: 'rgba(15, 23, 42, 0.9)', 
                                border: '1px solid var(--glass-border)',
                                borderRadius: '8px',
                                fontSize: '0.8rem'
                            }}
                        />
                        <Legend verticalAlign="bottom" height={36}/>
                    </PieChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}

export default AttackDistribution;
