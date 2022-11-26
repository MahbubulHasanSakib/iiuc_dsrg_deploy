import Container from 'react-bootstrap/Container';
import Nav from 'react-bootstrap/Nav';
import Navbar from 'react-bootstrap/Navbar';
import NavDropdown from 'react-bootstrap/NavDropdown';
import { Link } from 'react-router-dom';
import Logo from '../assets/logo.jpg'
import { useParams,useNavigate } from 'react-router-dom';
import { useLocation } from 'react-router-dom';
import { useAppContext } from '../Context/userContext';
const Header=()=> {
  const params=useParams()
  const navigate=useNavigate()
  const currentLocation=useLocation().pathname;
  const userData=useAppContext()
  const handleLogOut=()=>{
    localStorage.removeItem('userInfo');
    userData.userInfo.setUser(null)
    navigate('/login')
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
             to="/membersList">
              Members List
            </Nav.Link>
            <Nav.Link 
             onClick={handleLogOut}>
              Logout
            </Nav.Link>
          </Nav>
          
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}

export default Header;