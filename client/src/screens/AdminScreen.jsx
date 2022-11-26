import React,{useEffect} from 'react'
import { Container } from 'react-bootstrap'
import AddMember from '../components/AdminComponents/AddMember'
import Header from "../components/AdminComponents/Header"
import { useParams,useNavigate} from 'react-router-dom'
const AdminScreen = () => {
  const navigate=useNavigate()
  const userInfo=localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null

  useEffect(()=>
  {
      if(!userInfo)
      {
           navigate('/login')
      }
  },[navigate,userInfo])

  return (
    <>
    <Header/>
   <AddMember/>
   </>
  )
}

export default AdminScreen