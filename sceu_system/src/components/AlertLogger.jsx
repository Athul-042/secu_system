import { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

function AlertLogger({ traced = [] }) {
  const [alerts, setAlerts] = useState([]);
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    if (traced && traced.length > 0) {
      const newAlerts = traced.map(item => ({
        message: `Alert: Abnormal traffic from ${item.sourceIP}`,
        details: `URL: ${item.url}, Session: ${item.session}, Timestamp: ${new Date().toISOString()}`,
      }));
      setAlerts(newAlerts);

      // Prepare chart data: group alerts by time (e.g., by minute)
      const timeGroups = {};
      newAlerts.forEach(alert => {
        const time = new Date(alert.details.split(', Timestamp: ')[1]).toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
        timeGroups[time] = (timeGroups[time] || 0) + 1;
      });
      const data = Object.keys(timeGroups).map(time => ({ time, alerts: timeGroups[time] }));
      setChartData(data);
    }
  }, [traced]);

  return (
    <div>
      <h2>Alerts and Logs</h2>
      {alerts.length === 0 ? (
        <p>No alerts generated yet.</p>
      ) : (
        <>
          <LineChart width={600} height={300} data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="alerts" stroke="#8884d8" />
          </LineChart>
          <ul>
            {alerts.map((alert, index) => (
              <li key={index}>
                {alert.message} - {alert.details}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export default AlertLogger;
