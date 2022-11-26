import React from 'react'
import { Container } from 'react-bootstrap'
import Separator from '../CommonComponents/Separator'
const Mission = () => {
  return (
    <Container className="mission">
         <div className='mission_img'>
      
        </div>
              <div className='mission_content'>
              <div className='title-div'>
              <Separator/>
        <div> <h3>Our Mission</h3></div>
         <Separator/>
         </div>
         <p>Our mission is to lead, promote and deliver multidisciplinary research solutions by learning computer programming, English, Statistics, Data Science, Research Methodology, Research ethics,
             GIS and RS, Scientific data analysis with Python, Matlab, NCL, and so on.
         </p>
        </div>
    </Container>
  )
}

export default Mission