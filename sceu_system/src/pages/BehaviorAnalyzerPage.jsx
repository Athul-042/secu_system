import { useNavigate } from 'react-router-dom';
import BehaviorAnalyzer from '../components/BehaviorAnalyzer';
import { useData } from '../contexts/DataContext';

function BehaviorAnalyzerPage() {
  const navigate = useNavigate();
  const { analysis } = useData();

  const handleNext = () => {
    navigate('/patterns');
  };

  return (
    <div className="page-container">
      <h1>Behavior Analysis</h1>
      <BehaviorAnalyzer analysis={analysis} />
      <button className="next-button" onClick={handleNext} disabled={analysis.length === 0}>
        Next: Pattern Identification
      </button>
    </div>
  );
}

export default BehaviorAnalyzerPage;
