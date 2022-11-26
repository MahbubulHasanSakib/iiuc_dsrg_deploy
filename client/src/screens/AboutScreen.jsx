import React from 'react'
import Header from '../components/CommonComponents/Header'
import AboutUs from '../components/AboutComponents/AboutUs'
import Mission from '../components/AboutComponents/Mission'
import Vision from '../components/AboutComponents/Vision'
import Footer from '../components/CommonComponents/Footer'
const AboutScreen = () => {
  return (
    <>
    <Header/>
    <h2 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>About Us</h2>
    <AboutUs/>
    <Mission/>
    <Vision />
    <Footer />
    </>
  )
}

export default AboutScreen