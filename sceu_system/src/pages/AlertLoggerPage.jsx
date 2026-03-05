import AlertLogger from '../components/AlertLogger';
import { useData } from '../contexts/DataContext';

function AlertLoggerPage() {
  const { traced } = useData();

  return (
    <div className="page-container">
      <h1>Alert Logging</h1>
      <AlertLogger alerts={traced} />
      <p>Analysis complete. Check the logs for any alerts.</p>
    </div>
  );
}

export default AlertLoggerPage;
