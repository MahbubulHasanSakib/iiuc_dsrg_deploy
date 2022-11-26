import React from 'react'
import { Container } from 'react-bootstrap'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faBookBookmark } from '@fortawesome/free-solid-svg-icons'
const Recent = () => {
  return (
    <Container className="recent-papers">
      <h3 className='text-center'>Recent Publications</h3>
      <ul>
            <li><span><FontAwesomeIcon icon={faBookBookmark}/></span>Paper on Something ,"Conference on IEEE something","published by Springer</li>
            <li><span><FontAwesomeIcon icon={faBookBookmark}/></span>Paper on Something ,"Conference on IEEE something","published by Springer</li>
            <li><span><FontAwesomeIcon icon={faBookBookmark}/></span>Paper on Something ,"Conference on IEEE something","published by Springer</li>
            <li><span><FontAwesomeIcon icon={faBookBookmark}/></span>Paper on Something ,"Conference on IEEE something","published by Springer</li>
            <li><span><FontAwesomeIcon icon={faBookBookmark}/></span>Paper on Something ,"Conference on IEEE something","published by Springer</li>
        </ul>
    </Container>
    
  )
}

export default Recent