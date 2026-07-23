import { useNavigate } from 'react-router-dom';
import TrafficCapture from '../components/TrafficCapture';
import Navbar from '../components/Navbar';
import { useData } from '../contexts/DataContext';

function TrafficCapturePage() {
  const navigate = useNavigate();
  const { trafficData, setTrafficData } = useData();

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a' }}>
      <Navbar />
      <div className="dashboard-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <h1 style={{ color: '#f8fafc', fontSize: '1.8rem', marginTop: '10px' }}>Traffic Capture Analysis</h1>
        <TrafficCapture onData={setTrafficData} />
      </div>
    </div>
  );
}

export default TrafficCapturePage;
