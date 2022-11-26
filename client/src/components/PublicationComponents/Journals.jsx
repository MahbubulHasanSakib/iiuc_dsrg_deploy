import React from 'react'
import { Container } from 'react-bootstrap'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faBookBookmark } from '@fortawesome/free-solid-svg-icons'
const Journals = () => {
  return (
    <Container className='journals'>
         <h3 className='text-center'>Journals</h3>
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

export default Journals