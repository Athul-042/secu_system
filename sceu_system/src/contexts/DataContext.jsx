import { createContext, useContext, useState, useEffect } from 'react';
import { extractFeatures, calculateStatistics, detectAnomalies } from '../utils/trafficUtils';

const DataContext = createContext();

export const useData = () => useContext(DataContext);

export const DataProvider = ({ children }) => {
  const [trafficData, setTrafficData] = useState([]);
  const [features, setFeatures] = useState([]);
  const [analysis, setAnalysis] = useState([]);
  const [stats, setStats] = useState(null);
  const [simulatedThreats, setSimulatedThreats] = useState([]);

  // Live backend stats (Synced with app.py Point 1)
  const [liveStats, setLiveStats] = useState({
    total_packets: 0,
    anomaly_count: 0,
    blocked_count: 0,
    safe_level: 100,
    anomaly_rate: 0
  });

  const [backendAlerts, setBackendAlerts] = useState([]);

  useEffect(() => {
    if (trafficData.length > 0) {
      const currentStats = calculateStatistics(trafficData);
      setStats(currentStats);

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

  const allAlerts = [
    ...backendAlerts.map(a => ({
      source: a.source,
      type: a.severity?.toLowerCase() || 'critical',
      desc: `${a.attack_type || 'Attack'}: ${a.reason || 'Pattern Anomaly'} (${a.confidence}% confidence)`,
      time: new Date().toLocaleTimeString(),
      severity: a.severity
    })),
    ...simulatedThreats
  ];

  return (
    <DataContext.Provider value={{
      trafficData, setTrafficData,
      features, setFeatures,
      analysis, setAnalysis,
      patterns: analysis,
      traced: analysis,
      stats, setStats,
      simulatedThreats, setSimulatedThreats,
      allAlerts,
      liveStats, setLiveStats,
      backendAlerts, setBackendAlerts
    }}>
      {children}
    </DataContext.Provider>
  );
};
