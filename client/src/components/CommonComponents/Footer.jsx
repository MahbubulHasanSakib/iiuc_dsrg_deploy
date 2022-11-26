import React from 'react'
import Logo from '../assets/logo.jpg'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import {faFacebook,faTwitter, faLinkedin,faTelegramPlane} from '@fortawesome/free-brands-svg-icons'
const Footer = () => {
  return (
    <footer className="footer-section">
    <div className="container">
        <div className="footer-cta pt-3 pb-3">
            <div className="row">
                <div className="col-xl-4 col-md-4 mb-30">
                    <div className="single-cta">
                        <i className="fas fa-map-marker-alt"></i>
                        <div className="cta-text">
                            <h4>Find us</h4>
                            <span>Chittagong,Bangladesh</span>
                        </div>
                    </div>
                </div>
                <div className="col-xl-4 col-md-4 mb-30">
                    <div className="single-cta">
                        <i className="fas fa-phone"></i>
                        <div className="cta-text">
                            <h4>Call us</h4>
                            <span>9876543210 0</span>
                        </div>
                    </div>
                </div>
                <div className="col-xl-4 col-md-4 mb-30">
                    <div className="single-cta">
                        <i className="far fa-envelope-open"></i>
                        <div className="cta-text">
                            <h4>Mail us</h4>
                            <span>mail@info.com</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div className="footer-content pt-3 pb-3">
            <div className="row">
                <div className="col-xl-4 col-lg-4 mb-50">
                    <div className="footer-widget">
                        <div className="footer-logo">
                            <a href="#"><img src={Logo} 
                           alt="logo"
                            /></a>
                        </div>
                        <div className="footer-text">
                            <p>Lorem ipsum dolor sit amet, consec tetur adipisicing elit, sed do eiusmod tempor incididuntut consec tetur adipisicing
                            elit,Lorem ipsum dolor sit amet.</p>
                        </div>
                        <div className="footer-social-icon">
                            <span>Follow us</span>
                            <a href="#"><FontAwesomeIcon className="fab fa-facebook-f facebook-bg" icon={faFacebook} /></a>
                            <a href="#"><FontAwesomeIcon className="fab fa-twitter twitter-bg" icon={faTwitter} /></a>
                            <a href="#"><FontAwesomeIcon className="fab fa-google-plus-g google-bg" icon={faLinkedin} /></a>
                        </div>
                    </div>
                </div>
                <div className="col-xl-4 col-lg-4 col-md-6 mb-30">
                    <div className="footer-widget">
                        <div className="footer-widget-heading">
                            <h3>Useful Links</h3>
                        </div>
                        <ul>
                            <li><a href="#">Home</a></li>
                            <li><a href="#">about</a></li>
                            <li><a href="#">services</a></li>
                            <li><a href="#">portfolio</a></li>
                            <li><a href="#">Contact</a></li>
                            <li><a href="#">About us</a></li>
                            <li><a href="#">Our Services</a></li>
                            <li><a href="#">Expert Team</a></li>
                            <li><a href="#">Contact us</a></li>
                            <li><a href="#">Latest News</a></li>
                        </ul>
                    </div>
                </div>
                <div className="col-xl-4 col-lg-4 col-md-6 mb-50">
                    <div className="footer-widget">
                        <div className="footer-widget-heading">
                            <h3>Subscribe</h3>
                        </div>
                        <div className="footer-text mb-25">
                            <p>Don’t miss to subscribe to our new feeds, kindly fill the form below.</p>
                        </div>
                        <div className="subscribe-form">
                            <form action="#">
                                <input type="text" placeholder="Email Address"/>
                                <button><FontAwesomeIcon  icon={faTelegramPlane} /></button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div className="copyright-area">
        <div className="container">
            <div className="row">
                <div className="col-xl-12 col-lg-12 text-center">
                    <div className="copyright-text">
                        <p>Copyright &copy; 2022, All Right Reserved IIUCDSRG</p>
                    </div>
                </div>
                
            </div>
        </div>
    </div>
</footer>
  )
}

export default Footer