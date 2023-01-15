import React from 'react'
import ProfileImg from '../components/assets/profileImg.jpg'
import BrandImg from '../components/assets/brandImg.jpg'
import BackgroundImg from '../components/assets/BackgroundImg.jpeg'
import './css/styles.css'
import WithLayout from '../Layout/WithLayout'
const ProfileScreen = () => {
  return (
    <>
 <div>
     
        <main className="profil_page">
          <section className="left_box">
            <div className="profil_info" id="pro_info">
              <div className="backgound_and_profil">
                <i className="fa-solid fa-pencil" />
                <img className="background_img" src={BackgroundImg} alt="#" />
                <img className="profil_pic" src={ProfileImg} alt="#" />
              </div>
              <div className="personnal_info_profil">
                <i className="fa-solid fa-pencil" />
                <div className="name_and_school">
                  <h2>Sahadat Hossain</h2>
                  <p>
                    <img src={BrandImg} alt="#" />
                    <span>IIUC Data Science Research Group</span> 
                  </p>
                </div>
                <h4>Software Engineer</h4>
                <p>Chittagong,Bangladesh <a href="#">Contact info <br /> <br /></a>
                </p>
                <div className="profil_button">
                  <div className="my_goal">Open to</div>
                  <div className="new_section"> Add Profile Section</div>
                  <div className="more">More</div>
                </div>
                <div className="profil_blocks" style={{margin:'10px 0px'}}>
                  
                </div>
              </div>
            </div>
           
            <div className="infos">
              <div className="title"><h4>About</h4><i className="fa-solid fa-pen" /></div>
              <p>Sahadat Hossain passed S.S.C and H.S.C exam from Nasirabad Government High School and Chattagram Biggan College in 2010 and 2012  respectively. He is an outgoing student from the B.Sc. in Department of Computer  Science and Engineering (CSE) at International Islamic University Chittagong (IIUC), Bangladesh. He is a passionate programmer in Python. His current fields of interest include data mining in the medical sector and machine learning. He is a member of IIUC Data Science Research Group, working under the supervision of Shahidul Islam Khan, Associate Professor, 
                Department of CSE, IIUC and founder Head of IIUC Data Science Research Group.</p>
            </div>
            <div className="infos">
              <div className="title"><h4>Experience</h4>
                <span className="icons"> 
                  <i className="fa-solid fa-plus" />
                  <i className="fa-solid fa-pen" />
                </span>
              </div>
              <p><img src="https://i.f1g.fr/media/eidos/orig/2015/07/20/PHO81b3db84-2ec8-11e5-ad32-1d334e2eca66-805x453.jpg" alt="" />  &nbsp; <span>Lead Webmaster</span>  <br /> &nbsp;  &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;IIUC Data Science Research Group <br /> &nbsp; &nbsp; &nbsp;&nbsp;  &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;Aug 2022 - Present · 5 mos<br /></p>
            </div>
            <div className="infos">
              <div className="title">
                <h4>Education</h4>
                <span className="icons"> 
                  <i className="fa-solid fa-plus" />
                  <i className="fa-solid fa-pen" />
                </span>
              </div>
              <p><img src="./css/images/Jiangsu_Normal_University_logo.png" alt="" /><span> International Islamic University Chittagong </span><br />&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;Bachelor of Engineering, Computer Science and Engineering <br />&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;2020 - 2024 <br />&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp;Activities at institution :Lead Webmaster at IIUC DSRG</p>
            </div>
    
            <div className="skills">
              <div className="title">
                <h4>Skills</h4>
                <span className="icons double_icons"> 
                 
                  <span>
                    <i className="fa-solid fa-plus" />
                    <i className="fa-solid fa-pen" />
                  </span>
                </span>
              </div>
              <h5 className="tech_language">JavaScript</h5>
              <h5 className="tech_language">css</h5>
              <h5>Bootstrap</h5>
            </div>
            <div className="show_more_res more_skill">
              <p className="click_more">Show all 32 skills <i className="fa-solid fa-right-long" /></p>
            </div>
            <div className="languages">
              <div className="title">
                <h4>Languages</h4>
                <span> <i className="fa-solid fa-plus" /><i className="fa-solid fa-pen" /></span>
              </div>
              <div className="language">
                <h5>Bangla</h5>
                <p>Native</p>
              </div>
              <div className="language">
                <h5>English</h5>
                <p>Fluent</p>
              </div>
            </div>
           
          </section>
          
        </main>
      </div>
    </>
  )
}

export default WithLayout(ProfileScreen)