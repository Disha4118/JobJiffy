import React from 'react';
import './ServiceProviderLogin.css';

const ServiceProviderLogin = () => {
  return (
    <div className="service-login-container">
      <h2>Service Provider Login</h2>
      <form className="service-login-form">
        <input type="email" placeholder="Email" required />
        <input type="password" placeholder="Password" required />
        <button type="submit">Login</button>
      </form>
      <p>Don't have an account? <a href="/register/provider">Register here</a></p>
    </div>
  );
};

export default ServiceProviderLogin;
