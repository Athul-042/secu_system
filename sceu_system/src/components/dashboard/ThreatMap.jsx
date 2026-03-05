import { useState, useEffect, useRef } from 'react';
import Globe from 'react-globe.gl';

function ThreatMap() {
    const globeEl = useRef();
    const [arcs, setArcs] = useState([]);
    const [points, setPoints] = useState([]);

    // Mock "Home" location (e.g., Server in India or US)
    const HOME_LAT = 20.5937;
    const HOME_LNG = 78.9629; // India

    useEffect(() => {
        // Generate random attacks
        const interval = setInterval(() => {
            // Random Source
            const lat = (Math.random() - 0.5) * 160;
            const lng = (Math.random() - 0.5) * 360;

            const newArc = {
                startLat: lat,
                startLng: lng,
                endLat: HOME_LAT,
                endLng: HOME_LNG,
                color: ['#ef4444', '#f59e0b', '#3b82f6'][Math.floor(Math.random() * 3)], // Red, Amber, Blue
                dashLength: Math.random() * 0.5 + 0.5,
                dashGap: Math.random() * 0.5 + 0.5,
                dashAnimateTime: Math.random() * 4000 + 500
            };

            setArcs(current => [...current.slice(-10), newArc]); // Keep last 10 arcs

            // Add impact point ring
            setPoints(current => [...current.slice(-5), {
                lat: HOME_LAT,
                lng: HOME_LNG,
                size: Math.random() * 0.5,
                color: newArc.color
            }]);

        }, 1500);

        // Initial globe setup
        if (globeEl.current) {
            globeEl.current.pointOfView({ lat: HOME_LAT, lng: HOME_LNG, altitude: 2 });
            globeEl.current.controls().autoRotate = true;
            globeEl.current.controls().autoRotateSpeed = 0.5;
        }

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="dashboard-card" style={{ gridColumn: 'span 4', height: '500px', padding: 0, overflow: 'hidden', position: 'relative' }}>
            <div className="card-header" style={{ position: 'absolute', top: 20, left: 20, zIndex: 10, background: 'rgba(15, 23, 42, 0.8)', padding: '10px', borderRadius: '8px', backdropFilter: 'blur(4px)' }}>
                <span className="card-title" style={{ color: '#fff' }}>Live Global Threat Map</span>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Real-time attack visualization</div>
            </div>

            <Globe
                ref={globeEl}
                globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
                arcsData={arcs}
                arcColor="color"
                arcDashLength="dashLength"
                arcDashGap="dashGap"
                arcDashAnimateTime="dashAnimateTime"
                arcStroke={0.5}

                ringsData={points}
                ringColor="color"
                ringMaxRadius="maxRadius"
                ringPropagationSpeed="propagationSpeed"
                ringRepeatPeriod="repeatPeriod"

                width={1100} // Approximate static width, better to use ResizeObserver but hardcoded for MVP
                height={500}
                backgroundColor="#0f172a"
            />
        </div>
    );
}

export default ThreatMap;
