import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { DataProvider, useData } from './contexts/DataContext';
import Login from './components/Login';
import TrafficCapture from './components/TrafficCapture';
import TrafficCapturePage from './pages/TrafficCapturePage';
import SecureVaultPage from './pages/SecureVaultPage';
import Dashboard from './components/dashboard/Dashboard';
import './App.css';

// Component to handle global traffic capture
const GlobalTrafficCapture = () => {
  const { setTrafficData } = useData();
  return <TrafficCapture onData={setTrafficData} background={true} />;
};

function App() {
  return (
    <DataProvider>
      <GlobalTrafficCapture />
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
  );
}

export default App;
