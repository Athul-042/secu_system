import { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './TrafficCapture.css';

const socket = io('http://localhost:5000'); // Connect to Flask Backend

function TrafficCapture({ onData, background = false }) {
  const [trafficData, setTrafficData] = useState([]);
  // Auto-start if background is true
  const [isCapturing, setIsCapturing] = useState(background);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    socket.on('connect', () => {
      console.log('Connected to Traffic Sniffer Backend');
      setIsConnected(true);
    });

    socket.on('disconnect', () => {
      console.log('Backend Disconnected');
      setIsConnected(false);
    });

    socket.on('new_packet', (packet) => {
      setTrafficData((prev) => {
        const newData = [packet, ...prev].slice(0, 50); // Keep last 50 packets
        if (onData) onData(newData);
        return newData;
      });
    });

    return () => {
      socket.off('connect');
      socket.off('new_packet');
      socket.off('disconnect');
    };
  }, [onData]);

  // Handle start/stop based on isCapturing state
  useEffect(() => {
    if (isCapturing && isConnected) {
      socket.emit('start_capture');
    } else if (!isCapturing && isConnected) {
      socket.emit('stop_capture');
    }
  }, [isCapturing, isConnected]);

  const toggleCapture = () => {
    if (isCapturing) {
      socket.emit('stop_capture');
    } else {
      socket.emit('start_capture');
    }
    setIsCapturing(!isCapturing);
  };

  if (background) return null;

  return (
    <div className="traffic-capture-container">
      <div className="capture-header">
        <h2>
          N/W Traffic Capture (Real-Time)
          <span className={`status-badge ${isConnected ? 'connected' : 'disconnected'}`}>
            {isConnected ? 'Attributes: Connected' : 'Attributes: Disconnected'}
          </span>
        </h2>
        <button
          onClick={toggleCapture}
          className={isCapturing ? 'btn-stop' : 'btn-start'}
        >
          {isCapturing ? 'Stop Capture' : 'Start Capture'}
        </button>
      </div>

      {trafficData.length === 0 ? (
        <p className="no-data">Waiting for packets... (Ensure Backend is running)</p>
      ) : (
        <ul className="packet-list">
          {trafficData.map((item, index) => (
            <li key={index} className="packet-item">
              <span className="protocol">{item.protocol}</span>
              <span className="source">{item.source}</span>
              <span className="arrow">→</span>
              <span className="destination">{item.destination}</span>
              <span className="size">({item.size} bytes)</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default TrafficCapture;

