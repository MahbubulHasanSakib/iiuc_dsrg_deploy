import React from 'react'
import ProfileImg from '../assets/profileImg.jpg'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faQuoteLeft } from '@fortawesome/free-solid-svg-icons'

const WellWisher = () => {
  return (
    <div className='wishing-post'>
    <div className='wishing-content'>
    
        <p><span><FontAwesomeIcon icon={faQuoteLeft} /></span>Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing 
            software like Aldus PageMaker including versions of Lorem Ipsum.</p>

    </div>
    <img src={ProfileImg} alt="profile"/>
    <h5>Professor Dr Golam Dastagir</h5>
     <h6>ADVISOR OF RESEARCH SOCIETY</h6>
   </div>
  )
}

export default WellWisher