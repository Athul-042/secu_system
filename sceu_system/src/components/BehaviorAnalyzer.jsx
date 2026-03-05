import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

function BehaviorAnalyzer({ features = [] }) {
  const [analysis, setAnalysis] = useState([]);

  useEffect(() => {
    if (features && features.length > 0) {
      // Simple model: Flag if response time > 2000ms or size > 500KB
      const analyzed = features.map(feature => ({
        ...feature,
        anomaly: feature.responseTime > 2000 || feature.requestSize > 500000,
      }));
      setAnalysis(analyzed);
    }
  }, [features]);

  const chartData = analysis.reduce((acc, item) => {
    const existing = acc.find((entry) => entry.name === item.url);
    if (existing) {
      existing.count += 1;
    } else {
      acc.push({ name: item.url, count: 1 });
    }
    return acc;
  }, []);

  return (
    <div>
      <h2>Behavior Analysis</h2>
      {analysis.length === 0 ? (
        <p>No analysis data available yet.</p>
      ) : (
        <>
          <BarChart width={400} height={300} data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="count" fill="#8884d8" />
          </BarChart>
          <ul>
            {analysis.map((item, index) => (
              <li key={index}>
                URL: {item.url}, Anomaly: {item.anomaly ? 'Yes' : 'No'}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export default BehaviorAnalyzer;
