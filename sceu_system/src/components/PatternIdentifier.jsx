import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';

function PatternIdentifier({ analysis = [] }) {
  const [patterns, setPatterns] = useState([]);

  useEffect(() => {
    if (analysis && analysis.length > 0) {
      const abnormal = analysis.filter(item => item.anomaly);
      setPatterns(abnormal);
    }
  }, [analysis]);

  const COLORS = ['#0088FE', '#FF8042'];
  const chartData = [
    { name: 'Abnormal', value: patterns.length },
    { name: 'Normal', value: analysis.length - patterns.length },
  ];

  return (
    <div>
      <h2>Abnormal Patterns</h2>
      {analysis.length === 0 ? (
        <p>No analysis data available yet.</p>
      ) : (
        <>
          <PieChart width={400} height={400}>
            <Pie
              data={chartData}
              cx={200}
              cy={200}
              labelLine={false}
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
          <ul>
            {patterns.map((pattern, index) => (
              <li key={index}>
                Abnormal URL: {pattern.url}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export default PatternIdentifier;
