import { createContext, useContext, useState, useEffect } from 'react';
import { extractFeatures, calculateStatistics, detectAnomalies } from '../utils/trafficUtils';

const DataContext = createContext();

export const useData = () => useContext(DataContext);

export const DataProvider = ({ children }) => {
  const [trafficData, setTrafficData] = useState([]);
  const [features, setFeatures] = useState([]);
  const [analysis, setAnalysis] = useState([]); // Anomalies
  const [stats, setStats] = useState(null);
  const [simulatedThreats, setSimulatedThreats] = useState([]);

  useEffect(() => {
    if (trafficData.length > 0) {
      // 1. Calculate Stats
      const currentStats = calculateStatistics(trafficData);
      setStats(currentStats);

      // 2. Extract Features & Detect Anomalies
      const processed = extractFeatures(trafficData).map(f => {
        const anomalies = detectAnomalies({ ...f, size: f.requestSize });
        return { ...f, anomalies, isAnomaly: anomalies.length > 0 };
      });

      setFeatures(processed);
    }
  }, [trafficData]);

  useEffect(() => {
    if (features.length > 0) {
      const abnormal = features.filter(f => f.isAnomaly);
      setAnalysis(abnormal);
    }
  }, [features]);

  // Combine real anomalies with simulated ones
  const allAlerts = [
    ...analysis.map(a => ({
      source: a.source,
      type: 'critical',
      desc: a.anomalies.join(', '),
      time: new Date().toLocaleTimeString()
    })),
    ...simulatedThreats
  ];

  return (
    <DataContext.Provider value={{
      trafficData, setTrafficData,
      features, setFeatures,
      analysis, setAnalysis, // Real anomalies
      patterns: analysis, // Alias for older components
      traced: analysis, // Alias for older components
      stats, setStats,
      simulatedThreats, setSimulatedThreats,
      allAlerts
    }}>
      {children}
    </DataContext.Provider>
  );
};
