import React from 'react'
import { Container } from 'react-bootstrap'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faBookBookmark } from '@fortawesome/free-solid-svg-icons'
const Conference = () => {
  return (
    <Container className='conference-papers'>
        <h3 className='text-center'>Conference Papers</h3>
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

export default Conference