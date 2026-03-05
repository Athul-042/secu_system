import { useNavigate } from 'react-router-dom';
import FeatureExtractor from '../components/FeatureExtractor';
import { useData } from '../contexts/DataContext';

function FeatureExtractorPage() {
  const navigate = useNavigate();
  const { features } = useData();

  const handleNext = () => {
    navigate('/behavior');
  };

  return (
    <div className="page-container">
      <h1>Feature Extraction</h1>
      <FeatureExtractor features={features} />
      <button className="next-button" onClick={handleNext} disabled={features.length === 0}>
        Next: Behavior Analysis
      </button>
    </div>
  );
}

export default FeatureExtractorPage;
