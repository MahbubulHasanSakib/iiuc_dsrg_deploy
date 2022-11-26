import React from 'react'
import Header from '../components/CommonComponents/Header'
import Recent from '../components/PublicationComponents/Recent'
import Journals from '../components/PublicationComponents/Journals'
import Conference from '../components/PublicationComponents/Conference'
import Footer from '../components/CommonComponents/Footer'
const PublicationScreen = () => {
  return (
   <>
    <Header/>
     <h2 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Publications</h2>
     <Recent/>
     <Journals />
     <Conference/>
    <Footer />
   </>
  )
}

export default PublicationScreen