import { useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from "react-router-dom";
import './home.css';
import About from './About';
import ContactUs from './ContactUs';
import Footer from './Footer';

export default function Home() {
  const [activeTab, setActiveTab] = useState('weProvide'); 
  const navigate = useNavigate();
  return (
    <div className="app dark-theme">
      <nav className="navbar">
        <div className="logo">JOB<span>JIFFY</span></div>
        <ul className="nav-links">
          <li><a className="nav" href="#header">Home</a></li>
          <li><a className="nav" href="#about">About Us</a></li>
          <li><a className="nav" href="#header">Help</a></li>
          <li><a className="nav" href="#contact">Contact Us</a></li>
        </ul>
        <button className="login-btn" onClick={() => navigate('/login')}>Login</button>
      </nav>

      <header className="header" id="header">
        <motion.h1
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          HIRE EXPERT SERVICES
        </motion.h1>
      </header>

      <div className="tabs">
        <div
          className={`tab ${activeTab === 'whyWe' ? 'active' : ''}`}
          onClick={() => setActiveTab('whyWe')}
        >
          <a href="#about" className='active'>WHY WE?</a>
        </div>
        <div
          className={`tab ${activeTab === 'weProvide' ? 'active' : ''}`}
          onClick={() => setActiveTab('weProvide')}
        >
          WE PROVIDE
        </div>
        <div
          className={`tab ${activeTab === 'reviews' ? 'active' : ''}`}
          onClick={() => setActiveTab('reviews')}
        >
          REVIEWS
        </div>
      </div>

      <main className="services">
         <div className="service-card neon-card electrician">
          <span className="service-text" onClick={()=>navigate('/services/electrician')}>Electrician</span>
        </div>
        <div className="service-card neon-card plumber">
          <span className="service-text" onClick={()=>navigate('/services/plumber')}>Plumber</span>
        </div>
        <div className="service-card neon-card plumber">
          <span className="service-text" onClick={()=>navigate('/services/carpenter')}>Carpenter</span>
        </div>
        <div className="service-card neon-card plumber">
          <span className="service-text" onClick={()=>navigate('/services/cleaner')}>Cleaner</span>
        </div>
        <div className="service-card neon-card plumber">
          <span className="service-text">service</span>
        </div>
        <div className="service-card neon-card plumber">
          <span className="service-text">service2</span>
        </div> 
      </main>

      <div id="about">
        <About />
      </div>
      <div id="#contact">
        <ContactUs/>
      </div>
      <div id="footer">
        <Footer/>
      </div>
    </div>
  );
}
