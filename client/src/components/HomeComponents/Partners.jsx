import React from 'react'
import { Container } from 'react-bootstrap'
import Partner from '../assets/partner.png'
import Separator from '../CommonComponents/Separator'
const Partners = () => {
  return (
    <Container className='partners'>
      <div className='title-div'>
        <Separator />
        <div> <h3 className='text-center'>Our Partners</h3></div>
        <Separator />
      </div>
    <div className='partnersImg'>
  <div className="partner">
  <img style={{width:'100px',height:'100px',borderRadius:'50%'}} src={Partner} alt="partner"/>
  </div>
  <div className="partner">
  <img style={{width:'100px',height:'100px',borderRadius:'50%'}} src={Partner} alt="partner"/>
  </div>
  <div className="partner">
  <img style={{width:'100px',height:'100px',borderRadius:'50%'}} src={Partner} alt="partner"/>
  </div>
  <div className="partner">
  <img style={{width:'100px',height:'100px',borderRadius:'50%'}} src={Partner} alt="partner"/>
  </div>
  <div className="partner">
  <img style={{width:'100px',height:'100px',borderRadius:'50%'}} src={Partner} alt="partner"/>
  </div>
    </div>
    </Container>
  )
}

export default Partners