import { HashRouter as Router, Routes, Route } from 'react-router-dom';
import { DataProvider, useData } from './contexts/DataContext';
import { ThemeProvider } from './contexts/ThemeContext';
import Login from './components/Login';
import TrafficCapture from './components/TrafficCapture';
import TrafficCapturePage from './pages/TrafficCapturePage';
import SecureVaultPage from './pages/SecureVaultPage';
import Dashboard from './components/dashboard/Dashboard';
import AlertToast from './components/AlertToast';
import './App.css';

// Component to handle global traffic capture
const GlobalTrafficCapture = () => {
  const { setTrafficData, setLiveStats, setBackendAlerts } = useData();
  return <TrafficCapture 
    onData={setTrafficData} 
    onStats={setLiveStats} 
    onAlert={(a) => setBackendAlerts(prev => [a, ...prev].slice(0, 20))}
    background={true} 
  />;
};

function App() {
  return (
    <ThemeProvider>
      <DataProvider>
        <GlobalTrafficCapture />
        <AlertToast />
        <Router>
          <div className="app">
            <Routes>
              <Route path="/" element={<Login />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/secure-vault" element={<SecureVaultPage />} />
              <Route path="/traffic" element={<TrafficCapturePage />} />
              <Route path="/login" element={<Login />} />
            </Routes>
          </div>
        </Router>
      </DataProvider>
    </ThemeProvider>
  );
}

export default App;
