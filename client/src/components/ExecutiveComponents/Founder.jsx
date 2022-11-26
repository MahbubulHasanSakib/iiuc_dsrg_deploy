import React from 'react'
import { Container } from 'react-bootstrap'
import ProfileImg from '../assets/profileImg.jpg'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faLocation,faEnvelope } from '@fortawesome/free-solid-svg-icons'
const Founder = () => {
  return (
         <>
        <h3 className="text-center" style={{padding:"20px 0px",backgroundColor:"#f6f6f6"}}>Founder and Head</h3>
        <Container>
        <div className="founderProfile">
        <img src={ProfileImg} alt="" />
        <div className='profile_right'>
        <h2>Dr. Shahidul Islam Khan</h2>
        <p> <span><FontAwesomeIcon icon={faLocation}/>Chittagong,Bangladesh</span> </p>
        <p><span><FontAwesomeIcon icon={faEnvelope}/></span>nayeemkh@gmail.com</p>
        </div>
        </div>
        <div className='education'>  
        <h2>Education</h2>
        <p>
        Dr. Shahidul Islam KHAN obtained his B.Sc. Engineering
Degree in Computer Science and Engineering (CSE) from
Ahsaah University of Science and Technology (AUST) in
2003. He obtained his M.Sc. and Ph.D. from Bangladesh
University of Engineering and Technology (BUET), Dhaka,
Bangladesh in 2011 and 2020. </p>
        </div>
        <div className='bio'>  
        <h2>Bio</h2>
        <p>
        His current fields of research
are Data Science, Database Systems, Machine Learning, Data
Security 	&#38; Privacy, and Health Informatics. Currently, he is
serving as the Head of the IIUC Data Science Research
Group. He has more than fifty published papers in peerreviewed journals and at reputed international conferences.
He is also an Associate Professor in the Dept. of CSE,
International Islamic University Chittagong (IIUC), Bangladesh.</p>
        </div>
        <div className='publication-of-founder'>  
        <h2>Publication</h2>
        <p>Google Scholar: <span><a href="https://https://scholar.google.com/citations?user=e2VQhc0AAAAJ">https://https://scholar.google.com/citations?user=e2VQhc0AAAAJ</a></span></p>
        <p>ORCID:<span><a href="https://https://orcid.org/0000-0002-8740-2744">https://https://orcid.org/0000-0002-8740-2744</a></span></p>
        <p>Research Gate:<span><a href="https://https://www.researchgate.net/profile/Shahidul-Khan">https://https://www.researchgate.net/profile/Shahidul-Khan</a></span></p>
        <p>Scopus:<span><a href="https://https://www.scopus.com/authid/detail.uri?authorId=7404042760">https://https://www.scopus.com/authid/detail.uri?authorId=7404042760</a></span></p>
        <p></p>
        </div>
    </Container>
    </>
  )
}

export default Founder