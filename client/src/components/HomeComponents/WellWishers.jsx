import React from 'react'
import WellWisher from './WellWisher'
import Separator from '../CommonComponents/Separator'
import { Container } from 'react-bootstrap'
const WellWishers = () => {
  return (
    <div className="wellWishers">
     <Container>
     <div className='title-div'>
        <Separator />
        <div> <h3 className='text-center'>WELL WISHER VOICE</h3></div>
        <Separator />
      </div>
     </Container>
      <Container className="wishing-posts">
      <WellWisher />
      <WellWisher />
      <WellWisher />
      <WellWisher />
      <WellWisher />
      </Container>
    </div>
  )
}

export default WellWishers