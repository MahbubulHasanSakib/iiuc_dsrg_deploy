import React from 'react'
import HashLoader from 'react-spinners/HashLoader';
const Loader = () => {
  return (
    <div className="loader" style={{
        display:"flex",
        justifyContent:"center",
        alignItems:"center",
        padding:"70px 0px"
    }}>
        <HashLoader color="#dc2516"/>
    </div>
  )
}

export default Loader