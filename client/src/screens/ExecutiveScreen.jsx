import React from 'react'
import { useLocation } from 'react-router-dom'
import Header from '../components/CommonComponents/Header'
import Footer from '../components/CommonComponents/Footer'
import Founder from '../components/ExecutiveComponents/Founder'
import Advisory from '../components/ExecutiveComponents/Advisory'
import TeacherTrainer from '../components/ExecutiveComponents/TeacherTrainer'
import Commitee from '../components/ExecutiveComponents/Commitee'
const ExecutiveScreen = () => {
  const path=useLocation().pathname
  console.log(path)
  return (
  <>
    <Header/>
    {
      path==="/founder-and-head" &&
      <Founder/>
    }
    {
      path==="/advisory-panel" &&
      <Advisory/>
    }
    {
      path==="/teacher-trainer" &&
     <TeacherTrainer/>
    }
    {
      path==="/commitee-members" &&
      <Commitee/>
    }
    <Footer />
  </>
  )
}

export default ExecutiveScreen