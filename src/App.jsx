import { BrowserRouter, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import SignUp from "./pages/Signup";
import ServiceProfiles from "./pages/ServiceProfiles";
import Booking from './pages/Booking';
import Choice from "./pages/Choice";

const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Choice/>} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/services/:serviceType" element={<ServiceProfiles />} />
        <Route path="/services/:serviceType/booking" element={<Booking />} />
        <Route path="/login/user" element={<Login/>} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
