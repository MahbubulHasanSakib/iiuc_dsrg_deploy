import React from 'react'
import AboutUs from '../components/AboutComponents/AboutUs'
import Mission from '../components/AboutComponents/Mission'
import Vision from '../components/AboutComponents/Vision'
import WithLayout from '../Layout/WithLayout'
const AboutScreen = () => {
  return (
    <>
    <h2 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>About Us</h2>
    <AboutUs/>
    <Mission/>
    <Vision />
    </>
  )
}

export default WithLayout(AboutScreen);