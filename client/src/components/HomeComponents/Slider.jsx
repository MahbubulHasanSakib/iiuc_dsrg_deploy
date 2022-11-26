import React from 'react'
import Carousel from 'react-bootstrap/Carousel';
const Slider = () => {
  return (
    <Carousel fade>
    <Carousel.Item>
    <img width="1920" height="850" src="https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society-.png" className="attachment-full size-full wp-post-image" alt="" loading="lazy" srcset="https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society-.png 1920w, https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society--768x340.png 768w, https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society--1536x680.png 1536w, https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society--24x11.png 24w, https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society--36x16.png 36w, https://researchsociety20.org/wp-content/uploads/2017/11/Welcome-to-Research-Society--48x21.png 48w" sizes="(max-width: 1920px) 100vw, 1920px"/>
      <Carousel.Caption>
        <h3>First slide label</h3>
        <p>Nulla vitae elit libero, a pharetra augue mollis interdum.</p>
      </Carousel.Caption>
    </Carousel.Item>
    <Carousel.Item>
    <img width="1920" height="850" src="https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission-.png" className="attachment-full size-full wp-post-image" alt="" loading="lazy" srcset="https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission-.png 1920w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission--768x340.png 768w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission--1536x680.png 1536w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission--24x11.png 24w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission--36x16.png 36w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Mission--48x21.png 48w" sizes="(max-width: 1920px) 100vw, 1920px"/>

      <Carousel.Caption>
        <h3>Second slide label</h3>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
      </Carousel.Caption>
    </Carousel.Item>
    <Carousel.Item>
    <img width="1920" height="850" src="https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision-.png" className="attachment-full size-full wp-post-image" alt="" loading="lazy" srcset="https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision-.png 1920w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision--768x340.png 768w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision--1536x680.png 1536w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision--24x11.png 24w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision--36x16.png 36w, https://researchsociety20.org/wp-content/uploads/2017/11/Our-Vision--48x21.png 48w" sizes="(max-width: 1920px) 100vw, 1920px"/>

      <Carousel.Caption>
        <h3>Third slide label</h3>
        <p>
          Praesent commodo cursus magna, vel scelerisque nisl consectetur.
        </p>
      </Carousel.Caption>
    </Carousel.Item>
  </Carousel>
  )
}

export default Slider