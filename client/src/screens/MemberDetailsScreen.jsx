import React, { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import ProfileImg from '../components/assets/profileImg.jpg'
import Header from '../components/CommonComponents/Header'
import Footer from '../components/CommonComponents/Footer'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faPhone,faEnvelope } from '@fortawesome/free-solid-svg-icons'
import axios from 'axios'
import Loader from '../components/CommonComponents/Loader'
import Resume from '../components/ResumeComponents/Resume'
import { Container } from 'react-bootstrap'
const MemberDetailsScreen = () => {
  const [member,setMember]=useState()
  const params=useParams()
  console.log(params.id)

  useEffect(()=>{
    try {
      const getMemberById=async()=>{
        const response=await axios.get(`/api/members/${params.username}`);
        setMember(response.data)
       }
       getMemberById()
     } catch (error) {
      console.log(error)
     }
  },[params.id])
  
  return (
    <>
    <Header/>
    {
      member?
      <>
       <Container>
       <Resume member={member}/>
       </Container>
      </>:<Loader/>
    }
    <Footer/>
   </>
  )
}

export default MemberDetailsScreen