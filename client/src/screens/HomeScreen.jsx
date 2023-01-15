import React from 'react'
import Slider from '../components/HomeComponents/Slider'
import WellWishers from '../components/HomeComponents/WellWishers'
import CounterWidget from '../components/HomeComponents/CounterWidget'
import Partners from '../components/HomeComponents/Partners'
import WithLayout from '../Layout/WithLayout'
const HomeScreen = () => {
  return (
    <>
    <Slider/>
    <WellWishers/>
    <CounterWidget/>
    <Partners/>
    </>
  )
}

export default WithLayout(HomeScreen)