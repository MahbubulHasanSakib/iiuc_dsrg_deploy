import React from 'react'
import { Container } from 'react-bootstrap'
import CountUp from 'react-countup'
import Separator from '../CommonComponents/Separator'
const CounterWidget = () => {
  return (
    <>
   <Container className="counterDivTitle">
   <div className='title-div'>
        <Separator />
        <div> <h3 className='text-center'>RESEARCH SOCIETY AT A GLANCE</h3></div>
        <Separator />
      </div>
   </Container>
    <Container  className='counterWidget' style={{textAlign:'center'}}>
        <div className='counterDiv'>
        <p className='countNumber'><CountUp start={0} end={100} duration={2} delay={0}/></p>
            <p className='countTitle'>Publications</p>
        </div>
        <div className='counterDiv'>
        <p className='countNumber'><CountUp start={0} end={300} duration={2} delay={0}/></p>
            <p className='countTitle'>Researchers</p>
           
        
        </div>
        <div className='counterDiv'>
        <p className='countNumber'><CountUp start={0} end={200} duration={2} delay={0}/></p>
            <p className='countTitle'>Partners</p>
        
        
        </div>
        <div className='counterDiv'>
        <p className='countNumber'><CountUp start={0} end={100} duration={2} delay={0}/></p>
            <p className='countTitle'>Alumni</p>
           
        
        </div>
   
    </Container>
         </>
  )
}

export default CounterWidget