import { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import './TrafficCapture.css';

const getBackendUrl = () => {
  if (window.electronAPI?.getBackendUrl) {
    return window.electronAPI.getBackendUrl();
  }
  return window.location.hostname === 'localhost' || !window.location.hostname
    ? 'http://localhost:5000'
    : `http://${window.location.hostname}:5000`;
};

let globalSocket;
const getSocket = () => {
  if (!globalSocket) {
    const backendUrl = getBackendUrl();
    globalSocket = io(backendUrl, {
      reconnectionDelay: 1000,
      reconnectionAttempts: Infinity,
      transports: ['websocket', 'polling']
    });
  }
  return globalSocket;
};

function TrafficCapture({ onData, onStats, onAlert, background = false }) {
  const socket = getSocket();
  const [trafficData, setTrafficData] = useState([]);
  const [isCapturing, setIsCapturing] = useState(background);
  const [isConnected, setIsConnected] = useState(false);

  // Use refs so listeners always call the latest callbacks
  // without needing to re-register on every render
  const onDataRef  = useRef(onData);
  const onStatsRef = useRef(onStats);
  const onAlertRef = useRef(onAlert);
  const trafficRef = useRef([]); // keeps latest trafficData without triggering renders
  useEffect(() => { onDataRef.current  = onData;  }, [onData]);
  useEffect(() => { onStatsRef.current = onStats; }, [onStats]);
  useEffect(() => { onAlertRef.current = onAlert; }, [onAlert]);

  useEffect(() => {
    const handleConnect = () => {
      console.log('Connected to Traffic Sniffer Backend');
      setIsConnected(true);
    };

    const handleDisconnect = () => {
      console.log('Backend Disconnected');
      setIsConnected(false);
    };

    const handlePacket = (packet) => {
      // Build new array via ref first — avoids calling another setter inside a setter
      trafficRef.current = [packet, ...trafficRef.current].slice(0, 50);
      setTrafficData(trafficRef.current);
      if (onDataRef.current) onDataRef.current(trafficRef.current);
      
      // Point 9: Link anomalies to global feed
      if (packet.is_anomaly && onAlertRef.current) {
        onAlertRef.current(packet);
      }
    };

    const handleStats = (stats) => {
      if (onStatsRef.current) onStatsRef.current(stats);
    };

    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('new_packet', handlePacket);
    socket.on('stats_update', handleStats);

    // If already connected when component mounts
    if (socket.connected) setIsConnected(true);

    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('new_packet', handlePacket);
      socket.off('stats_update', handleStats);
    };
  }, []); // Empty dependency — register listeners ONCE, never re-register

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
