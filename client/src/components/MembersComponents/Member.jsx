import React from 'react'
import {Container} from 'react-bootstrap'
import ProfileImg from '../assets/profileImg.jpg'
import { Link,useNavigate } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPhone,faEnvelope } from '@fortawesome/free-solid-svg-icons'
const Member = ({member}) => {
  const {_id}=member
console.log(member)
  const navigate=useNavigate()
  return (
    <Container className="member-container">
    <div className="member">
       <div className="member_left" style={{
        display:"flex",
        columnGap:"20px",
        alignItems:"center"
       }}>
       <img src={member.profileImg||ProfileImg} alt="" />
     <div className='memberInfo'>
     <Link to={`/members/${member.name}/${_id}`}>{member.name}</Link>
     <p><span><FontAwesomeIcon icon={faEnvelope}/></span>{member.email}</p>
     <p><span><FontAwesomeIcon icon={faPhone}/></span>{member.phone}</p>
     <button onClick={()=>navigate(`/members/${member.name}/${_id}`)} type="button" className="btn btn-info" style={{margin:"5px 0px"}}>View Profile</button>
     </div>
        </div>  
        <div className="member-interest">
        <p>Field of Interest</p>
        <p>{member.field_of_interest}</p>
          </div>         
    </div>
    </Container>
  )
}

export default Member