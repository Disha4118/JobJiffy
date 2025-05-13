import React from "react";
import { useNavigate } from "react-router-dom";
import "./Choice.css";

const Choice = () => {
  const navigate = useNavigate();

  return (
    <div className="login-choice-container">
      <h2>Login to <span className="highlight">JobJiffy</span></h2>
      <p>Select how you'd like to continue:</p>

      <div className="choice-buttons">
        <button onClick={() => navigate("/login/user")}>Login as User</button>
        <button onClick={() => navigate("/login/serviceprovider")}>Login as Service Provider</button>
      </div>
    </div>
  );
};

export default Choice;
