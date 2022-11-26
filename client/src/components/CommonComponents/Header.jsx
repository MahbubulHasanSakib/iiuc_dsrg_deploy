import Container from 'react-bootstrap/Container';
import Nav from 'react-bootstrap/Nav';
import Navbar from 'react-bootstrap/Navbar';
import NavDropdown from 'react-bootstrap/NavDropdown';
import { Link, Navigate } from 'react-router-dom';
import Logo from '../assets/logo.jpg'
import { useParams } from 'react-router-dom';
import { useLocation } from 'react-router-dom';
import { useState } from 'react';
import { useAppContext } from '../Context/userContext';
const Header=()=> {
  const params=useParams()
  const userData=useAppContext()
 // let userInfo=localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null
  const currentLocation=useLocation().pathname;
  const [userInfo,setUserInfo]=useState(localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null)
  const handleLogOut=()=>{
    localStorage.removeItem('userInfo');
    setUserInfo(null)
    userData.userInfo.setUser(null)
  }

  return (
    <Navbar className='sticky-nav' expand="lg">
      <Container>
        <Navbar.Brand as={Link} to="/">
          <img className='logoImg' src={Logo} alt="logo"/>
        </Navbar.Brand>
        <Navbar.Toggle aria-controls="navbarScroll" />
        <Navbar.Collapse id="navbarScroll">
          <Nav
            className="ms-auto my-2"
          >
            <Nav.Link as={Link}
            className={`${currentLocation==="/"?"activeNavLink":""}`}
             to="/">Home</Nav.Link>
            <Nav.Link as={Link}
             className={`${currentLocation==="/about"?"activeNavLink":""}`}
             to="/about">About</Nav.Link>
            <NavDropdown 
             className={`${(currentLocation!=="/about" && currentLocation!=="/publication" 
             && currentLocation!=="/" && currentLocation!=="/members" && !(params.id))?
             "activeNavLink":""}`} title="Executive Body" id="navbarScrollingDropdown">
              <NavDropdown.Item className={`${currentLocation==="/founder-and-head"?"activeNavLink":""}`} as={Link} to="/founder-and-head">Founder and Head</NavDropdown.Item>
              <NavDropdown.Item className={`${currentLocation==="/advisory-panel"?"activeNavLink":""}`} as={Link} to="/advisory-panel">Advisory Panel</NavDropdown.Item>
              <NavDropdown.Item className={`${currentLocation==="/teacher-trainer"?"activeNavLink":""}`} as={Link} to="/teacher-trainer">Teacher/Trainer</NavDropdown.Item>
              <NavDropdown.Item className={`${currentLocation==="/commitee-members"?"activeNavLink":""}`} as={Link} to="/commitee-members">Commitee Members</NavDropdown.Item>
            </NavDropdown>
            <Nav.Link as={Link}
            className={`${currentLocation==="/publication"?"activeNavLink":""}`}
             to="/publication">
              Publication
            </Nav.Link>
            <Nav.Link as={Link}
            className={`${currentLocation==="/members" || params.id?"activeNavLink":""}`}
             to="/members">
              Members
            </Nav.Link>
            {
              userInfo?
              <>
              <NavDropdown 
             className={`${(currentLocation!=="/about" && currentLocation!=="/publication" 
             && currentLocation!=="/" && currentLocation!=="/members" && !(params.id))?
             "activeNavLink":""}`} title="Admin" id="navbarScrollingDropdown">
              <NavDropdown.Item  as={Link} to="/admin">Add Member</NavDropdown.Item>
              <NavDropdown.Item >
              <p onClick={handleLogOut}>Logout</p>
              
              </NavDropdown.Item>
             </NavDropdown>
               </>:
              <Nav.Link as={Link}
             to="/login">
             <span style={{cursor:"pointer"}}>Login</span>
            </Nav.Link>
            }
          </Nav>
          
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}

export default Header;