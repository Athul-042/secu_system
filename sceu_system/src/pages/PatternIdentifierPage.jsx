import { useNavigate } from 'react-router-dom';
import PatternIdentifier from '../components/PatternIdentifier';
import { useData } from '../contexts/DataContext';

function PatternIdentifierPage() {
  const navigate = useNavigate();
  const { patterns } = useData();

  const handleNext = () => {
    navigate('/source');
  };

  return (
    <div className="page-container">
      <h1>Pattern Identification</h1>
      <PatternIdentifier patterns={patterns} />
      <button className="next-button" onClick={handleNext} disabled={patterns.length === 0}>
        Next: Source Tracing
      </button>
    </div>
  );
}

export default PatternIdentifierPage;
