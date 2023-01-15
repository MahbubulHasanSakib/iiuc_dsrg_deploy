import React from 'react'
import Recent from '../components/PublicationComponents/Recent'
import Journals from '../components/PublicationComponents/Journals'
import Conference from '../components/PublicationComponents/Conference'
import WithLayout from '../Layout/WithLayout'
const PublicationScreen = () => {
  return (
   <>
     <h2 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Publications</h2>
     <Recent/>
     <Journals />
     <Conference/>
   </>
  )
}

export default WithLayout(PublicationScreen)