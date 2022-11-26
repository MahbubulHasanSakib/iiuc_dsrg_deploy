import React from 'react'
import { Container } from 'react-bootstrap'
import ProfileImg from '../assets/profileImg.jpg'
const Commitee = () => {
  return (
    <>
    <h3 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Commitee Members</h3>
    <Container>
        <div className='commitee-members'>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Abid Ud Takey Emou</h3>
           <p>Chief</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Ekramul Haque Tusher</h3>
           <p>Vice Chief(Student Activity)</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Nazrana Mehjabin</h3>
           <p>Vice Chief(Management)</p>
        </div>
        
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Abu Nowhash Chowdhury</h3>
           <p>Research &#38; Publication Coordinator</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Sultan Mahmud Nahian</h3>
           <p>HCI Research Coordinator</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Abdur Rahman Robin</h3>
           <p>Administration &#38; Finance Coordinator</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Shahin Sha Hossain</h3>
           <p>Creative Designer(Lead)</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Raiwatul Labib</h3>
           <p>Membership &#38; Publicity Coordinator</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Mahbubul Hasan</h3>
           <p>Webmaster(Lead)</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Erfanul Taher</h3>
           <p>Webmaster</p>
        </div>
        <div className='commitee-member'>
           <img src={ProfileImg} alt="" />
           <h3>Md. Sharia Habib Ula</h3>
           <p>Event Coordinator</p>
        </div>
        </div>
    </Container>
</>
  )
}

export default Commitee