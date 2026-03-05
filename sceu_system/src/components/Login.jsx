import { useNavigate } from 'react-router-dom';
import './Login.css';

function Login() {
  const navigate = useNavigate();

  const handleLogin = () => {
    navigate('/dashboard');
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h1 className="login-title">Intrusion Detection System</h1>
        <p className="login-subtitle">Secure your network with advanced analysis</p>
        <div className="login-form">
          <input type="text" placeholder="Username" className="login-input" />
          <input type="password" placeholder="Password" className="login-input" />
        </div>
        <button className="login-button" onClick={handleLogin}>
          <span className="button-text">Login</span>
          <div className="button-glow"></div>
        </button>
      </div>
      <div className="background-animation">
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
      </div>
    </div>
  );
}

export default Login;
