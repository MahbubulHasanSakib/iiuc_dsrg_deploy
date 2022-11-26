import React, { useEffect, useState } from 'react'
import Header from '../components/CommonComponents/Header'
import Member from '../components/MembersComponents/Member'
import Footer from '../components/CommonComponents/Footer'
import Loader from '../components/CommonComponents/Loader'
import ScrollToTop from '../components/CommonComponents/ScrollToTop'
import axios from 'axios'
const MembersScreen = () => {
  const [members,setMembers]=useState([])
  useEffect(()=>{
   try {
    const getMembers=async()=>{
      const response=await axios.get('/api/members');
      setMembers(response.data)
     }
     getMembers()
   } catch (error) {
    console.log(error)
   }
  },[])
  return (
    <div className='members-screen'>
      <ScrollToTop/>
    <Header/>
    
     <h2 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Members</h2>
    {
      members && members.length>0?
      <div className='members'>
       { members.map((member)=>{
        return <Member member={member}/>
      })
      }
      </div>:<Loader/>
    }
    <Footer/>
   </div>
  )
}

export default MembersScreen