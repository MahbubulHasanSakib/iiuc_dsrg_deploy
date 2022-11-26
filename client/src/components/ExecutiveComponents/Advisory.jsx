import React from 'react'
import { Container } from 'react-bootstrap'
import ProfileImg from '../assets/profileImg.jpg'
const Advisory = () => {
  return (
         <>
          <h3 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Advisory Panel</h3>
          <Container>
          <div className='advisors'>
          <div className='advisor'>
            <img src={ProfileImg} alt="" />
           <h3>Dr. Abu Sayed Md. Latiful Haque</h3>
           <p>Professor and Former Head</p>
           <p>Dept. of CSE,BUET</p>
          </div>
          <div className='advisor'>
          <img src={ProfileImg} alt="" />
          <h3>Dr. Mohammad Shamsul Arefin</h3>
           <p>Professor and Former Head</p>
           <p>Dept. of CSE,CUET</p>
          </div>
          <div className='advisor'>
          <img src={ProfileImg} alt="" />
          <h3>Dr. Rashed Mostafa</h3>
           <p>Dean,Faculty of Engineering,CU</p>
           <p>Professor,Dept. of CSE,CU</p>
          </div>
          <div className='advisor'>
          <img src={ProfileImg} alt="" />
          <h3>Engr. Dr. Md Anisul Karim</h3>
           <p>Team Lead,Data Science</p>
           <p>Austrailian Federal Govt.</p>
          </div>
          <div className='advisor'>
          <img src={ProfileImg} alt="" />
          <h3>Engr. Mahedee Hasan</h3>
           <p>Head of Software Development and Joint Director(IT)</p>
           <p>ASA International</p>
          </div>
          </div>
    </Container>
    </>
  )
}

export default Advisory