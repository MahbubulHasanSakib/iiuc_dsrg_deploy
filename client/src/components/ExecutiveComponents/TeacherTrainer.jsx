import React from 'react'
import { Container } from 'react-bootstrap'
import ProfileImg from '../assets/profileImg.jpg'
const TeacherTrainer = () => {
  return (
    <>
    <h3 className='text-center' style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Teacher/Trainers</h3>
    <Container>
        <div className='teacher-trainers'>
          <div className="teacher-trainer">
          <img src={ProfileImg} alt="" />
           <h3>Dr. Mohammad Aman Ullah</h3>
           <p>Associate Professor</p>
           <p>Dept. of CSE,IIUC</p>
          </div>

          <div className="teacher-trainer">
          <img src={ProfileImg} alt="" />
           <h3>Dr. Muhammad Moazzam Hossen</h3>
           <p>Assistant Professor</p>
           <p>Dept. of CSE,IIUC</p>
          </div>

          <div className="teacher-trainer">
          <img src={ProfileImg} alt="" />
          <h3>Mohammad Manjur Alam</h3>
           <p>Assistant Professor</p>
           <p>Dept. of CSE,IIUC</p>
          </div>

          <div className="teacher-trainer">
          <img src={ProfileImg} alt="" />
          <h3>Sayed Allama Iqbal</h3>
           <p>Assistant Professor</p>
           <p>Dept. of EEE,IIUC</p>
          </div>

          <div className="teacher-trainer">
          <img src={ProfileImg} alt="" />
          <h3>Md. Rashedul Islam</h3>
           <p>Assistant Professor</p>
           <p>Dept. of CSE,IIUC</p>
          </div>

        </div>
</Container>
</>
  )
}

export default TeacherTrainer