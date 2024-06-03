import React from 'react';
import { Link } from 'react-router-dom';
import logo from '../../assets/logo.png';
import './Navbar.css';
const Navbar = ({ isAuthenticated }) => {
  console.log(isAuthenticated);

  return (
    <div className="navbar">
      <img src={logo} alt="MyFinancePal" className="logo" />
      <div className="buttons">
        {!isAuthenticated ? (
          <>
            <Link to="/login">
              <button>Login</button>
            </Link>
            <Link to="/register">
              <button>Register</button>
            </Link>
          </>
        ) : (
          <Link to="/transactions">
            <button>Transactions</button>
          </Link>
        )}
      </div>
    </div>
  );
};

export default Navbar;
