import React from 'react'
import Header from '../components/CommonComponents/Header'
import Slider from '../components/HomeComponents/Slider'
import WellWishers from '../components/HomeComponents/WellWishers'
import CounterWidget from '../components/HomeComponents/CounterWidget'
import Partners from '../components/HomeComponents/Partners'
import Footer from '../components/CommonComponents/Footer'
const HomeScreen = () => {
  return (
    <>
    <Header/>
    <Slider/>
    <WellWishers/>
    <CounterWidget/>
    <Partners/>
    <Footer/>
    </>
  )
}

export default HomeScreen