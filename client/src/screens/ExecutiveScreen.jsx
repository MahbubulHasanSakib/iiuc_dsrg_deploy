import React from 'react'
import { useLocation } from 'react-router-dom'
import Founder from '../components/ExecutiveComponents/Founder'
import Advisory from '../components/ExecutiveComponents/Advisory'
import TeacherTrainer from '../components/ExecutiveComponents/TeacherTrainer'
import Commitee from '../components/ExecutiveComponents/Commitee'
import WithLayout from '../Layout/WithLayout'
const ExecutiveScreen = () => {
  const path=useLocation().pathname
  console.log(path)
  return (
  <>

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

  </>
  )
}

export default WithLayout(ExecutiveScreen)