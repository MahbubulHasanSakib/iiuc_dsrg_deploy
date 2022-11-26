import React,{useEffect, useState} from 'react'
import ProfileImg from '../assets/profileImg.jpg'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faPlus } from '@fortawesome/free-solid-svg-icons'
import Modal from 'react-bootstrap/Modal';
import Button from 'react-bootstrap/Button';
import { Form } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import axios from 'axios'
import { useAppContext } from '../Context/userContext';

const Resume = ({member}) => {
  console.log("mem")
    console.log(member)
console.log("testContext")
const userData = useAppContext();
console.log(userData)
    const [memberDetails,setMemberDetails]=useState(member)
    const navigate=useNavigate()
  const userInfo=localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null
  const [show, setShow] = useState(false);

  const handleClose = () => setShow(false);
  const handleShow = () => setShow(true);

  const [memberInfo, setMemberInfo] = useState({
  company:"",
  startDate:"",
  endDate:"",
  designation:"",
  jobDescription:"",
})

const [errorMessage, setErrorMessage] = useState('')
const [successMessage, setSuccessMessage] = useState('')


const handleSubmit = async (e) => {

    const user=localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null

    e.preventDefault()
    console.log("member info")
     console.log(memberInfo)
    try {
        const config = {
            headers: {
                'Content-Type': 'application/json',
                 Authorization:`Bearer ${user.token}`
            }
        }
        const { data } = await axios.put(`/api/jobs/${member._id}`, memberInfo, config)
        console.log("updated")
        console.log(data);
        setMemberDetails(data.member)
        if (data.success) {
            setErrorMessage('')
            setSuccessMessage('Job added successfully')
            

        }
    }
    catch (error) {
        console.log(error.response);
        setSuccessMessage('')
        setErrorMessage(error.response.data.message);
    } 

}
const handleChange = (e) => {
    const key = e.target.name;
    const value = e.target.value;
    setMemberInfo({ ...memberInfo, [key]: value })
}
console.log("ok")
console.log(memberDetails)
  return (
   <>
   <Modal className="modal-class" show={show} onHide={handleClose}>
        <Modal.Header closeButton>
          <Modal.Title>Add new job experiance</Modal.Title>
        </Modal.Header>
        <Modal.Body>

        <Form onSubmit={handleSubmit}>
                            <div class="tab-pane fade show active" id="home" role="tabpanel" aria-labelledby="home-tab">
                               
                                <div class="row job-form">
                               

                                    <div class="col-md-12">
                                        
                                        <div class="form-group">
                                            <input type="text"
                                                onChange={handleChange} name="company" class="form-control" placeholder="Company" value={memberInfo.company} />
                                        </div>
                                        <div class="form-group">
                                            <input type="text" onChange={handleChange} name="startDate" class="form-control" placeholder="Start date" value={memberInfo.startDate} />
                                        </div>
                                        <div class="form-group">
                                            <input type="text" onChange={handleChange} name="endDate" class="form-control" placeholder="End date" value={memberInfo.endDate} />
                                        </div>
                                        <div class="form-group">
                                            <input type="text" name="designation" onChange={handleChange} class="form-control" placeholder="Designation" value={memberInfo.designation} />
                                        </div>
                                    </div>
                                    <div class="col-md-12">

                                        <div class="form-group">
                                            <textarea placeholder="Job Description" onChange={handleChange} name="jobDescription" value={memberInfo.jobDescription} rows={10} cols={40}></textarea>
                                        </div>

                                        <input type="submit" class="btnRegister" value="Register" />
                                    </div>
                                </div>
                            </div>

                        </Form>

        </Modal.Body>
        
      </Modal>
    <div  className="profile-page">
  <div  className="wrapper">
    <div  className="page-header page-header-small">
      <div  className="page-header-image" ></div>
      <div  className="container">
        <div  className="content-center">
          <div  className="cc-profile-image"><a href="#"><img src={memberDetails.profileImg||ProfileImg} alt="Image"/></a></div>
          </div>
      </div>
      <div  className="section">
        <div  className="container">
        <p style={{padding:"10px 0px",fontWeight:'bold'}}>Field of Interest:{memberDetails.field_of_interest}</p>
       </div>
      </div>
    </div>
  </div>
</div>
<div  className="section" id="about" style={{marginBottom:"20px"}}>
  <div  className="container">
    <div  className="card" data-aos="fade-up" data-aos-offset="10">
      <div  className="row">
        <div  className="col-lg-6 col-md-12">
          <div  className="card-body">
            <div  className="h4 mt-0 title">About</div>
      <p>{memberDetails.description}</p>
          </div>
        </div>
        <div  className="col-lg-6 col-md-12">
          <div  className="card-body">
            <div  className="h4 mt-0 title">Basic Information</div>
            <div  className="row mt-3">
              <div  className="col-sm-4"><strong  className="text-uppercase">Email:</strong></div>
              <div  className="col-sm-8">{memberDetails.email}</div>
            </div>
            <div  className="row mt-3">
              <div  className="col-sm-4"><strong  className="text-uppercase">Phone:</strong></div>
              <div  className="col-sm-8">{memberDetails.phone}</div>
            </div>
         
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<div  className="section" id="experience" style={{marginBottom:"20px"}}>
  <div  className="container cc-experience">
  {
  userData.userInfo.user && (
    <div className='add-experiance'>
      <p>Add experience</p>
      <p><FontAwesomeIcon onClick={handleShow} icon={faPlus}/></p>
      </div>
  )
  }
    <div  className="h4 text-center mb-4 title">{memberDetails.jobs.length>0 && "Work Experience"}</div>
    {
      memberDetails.jobs && memberDetails.jobs.length>0 &&
      memberDetails.jobs.map(job=>{
          console.log(job)
          return (
            (
              <div  className="card">
            <div  className="row">
              <div  className="col-md-3 job bg-primary" data-aos="fade-right" data-aos-offset="50" data-aos-duration="500">
                <div  className="card-body cc-experience-header">
                  <p>{job.startDate} - {job.endDate}</p>
                  <div  className="h5">{job.company}</div>
                </div>
              </div>
              <div  className="col-md-9 "  data-aos="fade-left" data-aos-offset="50" data-aos-duration="500">
                <div  className="card-body">
                  <div  className="h5">{job.designation}</div>
                  <p>{job.jobDescription}</p>
                </div>
              </div>
            </div>
          </div>
            )
          )
        })
    }

  </div>
</div>

   </>
    
  )
}

export default Resume