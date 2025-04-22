import './Login.css'; // CSS file import

const Login = () => {
  return (
    <div className="form-header-container">
      <div className="form-box">
        <div className="form-content">
          {/* Text Section */}
          <div className="form-text">
            <h1>
              Find Your Dream <span className="highlight-yellow">Job</span> with <span className="highlight-orange">JobJiffy</span>
            </h1>
            <p>Explore verified jobs, connect with employers, and get hired with ease.</p>
          </div>

          {/* Form Section */}
          <div className="form-card">
            <h2>Login to JobJiffy</h2>
            <form>
                <input type="email" placeholder="Email" />
                <input type="password" placeholder="Password" />
                <button type="submit">Login</button>
              </form>

              <p className="signup-text">
                Don't have an account? <a href="/signup" className="signup-link">Sign up</a>
              </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
