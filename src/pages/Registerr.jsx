import React, { useState } from 'react';
import './Registerr.css';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const steps = [
  { label: "Full Name", name: "name", type: "text" },
  { label: "Email", name: "email", type: "email" },
  { label: "Phone Number", name: "phone", type: "tel" },
  { label: "Password", name: "password", type: "password" },
  { label: "Service Category", name: "category", type: "select", options: ["Plumber", "Electrician", "Carpenter", "Washer", "Tailor"] },
  { label: "Experience (Years)", name: "experience", type: "number" },
  { label: "Rate/Bid Price ₹", name: "rate", type: "number" },
  { label: "Bio", name: "bio", type: "textarea" },
  { label: "Upload Profile Photo", name: "photo", type: "file" },
];

const Registerr = () => {
  const [step, setStep] = useState(0);
  const [formData, setFormData] = useState({});

  const handleChange = (e) => {
    const { name, value, files, type } = e.target;
    setFormData({ ...formData, [name]: type === "file" ? files[0] : value });
  };

  const handleNext = () => {
    if (step < steps.length - 1) setStep(step + 1);
    else toast.success("Registration Successful! ✅");
    console.log(formData);
  };

  const handleBack = () => {
    if (step > 0) setStep(step - 1);
  };

  const currentStep = steps[step];

  return (
    <div className="multi-step-container">
        <ToastContainer/>
      <div className="form-card">
        <h2>Service Provider Registration</h2>
        <label>{currentStep.label}</label>

        {currentStep.type === "select" ? (
          <select name={currentStep.name} onChange={handleChange} required>
            <option value="">Select</option>
            {currentStep.options.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        ) : currentStep.type === "textarea" ? (
          <textarea name={currentStep.name} rows="4" onChange={handleChange} />
        ) : (
          <input
            type={currentStep.type}
            name={currentStep.name}
            onChange={handleChange}
            required
          />
        )}

        <div className="buttons">
          {step > 0 && <button onClick={handleBack}>Back</button>}
          <button onClick={handleNext}>{step === steps.length - 1 ? "Submit" : "Next"}</button>
        </div>

        <div className="step-indicator">{step + 1} / {steps.length}</div>
      </div>
    </div>
  );
};

export default Registerr;
