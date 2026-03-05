import { useNavigate } from 'react-router-dom';
import TrafficCapture from '../components/TrafficCapture';
import { useData } from '../contexts/DataContext';

function TrafficCapturePage() {
  const navigate = useNavigate();
  const { trafficData, setTrafficData } = useData();

  const handleNext = () => {
    navigate('/features');
  };

  return (
    <div className="page-container">
      <h1>Traffic Capture</h1>
      <TrafficCapture onData={setTrafficData} />
      <button className="next-button" onClick={handleNext} disabled={trafficData.length === 0}>
        Next: Feature Extraction
      </button>
    </div>
  );
}

export default TrafficCapturePage;
