import { useNavigate } from 'react-router-dom';
import SourceTracer from '../components/SourceTracer';
import { useData } from '../contexts/DataContext';

function SourceTracerPage() {
  const navigate = useNavigate();
  const { traced } = useData();

  const handleNext = () => {
    navigate('/alerts');
  };

  return (
    <div className="page-container">
      <h1>Source Tracing</h1>
      <SourceTracer traced={traced} />
      <button className="next-button" onClick={handleNext} disabled={traced.length === 0}>
        Next: Alert Logging
      </button>
    </div>
  );
}

export default SourceTracerPage;
