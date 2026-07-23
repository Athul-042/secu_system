import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Login() {
  const navigate = useNavigate();
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const handleLogin = (e) => {
    e.preventDefault();
    setIsLoggingIn(true);
    // Simulate authentication networking delay
    setTimeout(() => {
      navigate('/dashboard');
    }, 1500);
  };

  return (
    <div className="login-container">
      {/* Dynamic Cyber Background */}
      <div className="cyber-grid"></div>
      <div className="background-animation">
        <div className="glowing-orb orb-1"></div>
        <div className="glowing-orb orb-2"></div>
        <div className="glowing-orb orb-3"></div>
      </div>

      <div className="login-card">
        {/* Animated Cyber Shield Logo */}
        <div className="shield-icon-container">
          <svg className="shield-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path className="shield-path" strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
          </svg>
          <div className="radar-sweep"></div>
        </div>

        <h1 className="login-title">Security IDS</h1>
        <p className="login-subtitle">Secure Network Intelligence Payload</p>

        <form className="login-form" onSubmit={handleLogin}>
          <div className="input-group">
            <span className="input-icon">🛡️</span>
            <input type="text" placeholder="Administrator ID" className="login-input" required />
          </div>
          <div className="input-group">
            <span className="input-icon">🔑</span>
            <input type="password" placeholder="Secure Passcode" className="login-input" required />
          </div>

          <button type="submit" className={`login-button ${isLoggingIn ? 'logging-in' : ''}`} disabled={isLoggingIn}>
            {isLoggingIn ? (
              <span className="auth-text">Establishing Connection...</span>
            ) : (
              <>
                <span className="button-text">Initialize Security System</span>
                <div className="button-glow"></div>
              </>
            )}
          </button>
        </form>

        <div className="system-status">
          <span className="status-dot green"></span>
          ML Detection Engine Ready
        </div>
      </div>
    </div>
  );
}

export default Login;
