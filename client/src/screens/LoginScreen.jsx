import React from 'react'
import {useState,useEffect} from 'react'
import {Form,Button,Spinner,Alert,Container} from 'react-bootstrap'
import { useParams,useNavigate} from 'react-router-dom'
import {Link} from 'react-router-dom'
import axios from 'axios'
import { useAppContext } from '../components/Context/userContext'
const LoginScreen = () => {
   
    const navigate=useNavigate()
     
    const userData=useAppContext()
    
    const [email,setEmail]=useState('')
    const [password,setPassword]=useState('')
    const [errorMessage, setErrorMessage] = useState('')
    const userInfo=localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null
    
    useEffect(()=>
    {
        if(userInfo)
        {
             navigate('/admin')
        }
    },[navigate,userInfo])
    const handleSubmit=async(e)=>
    {
        e.preventDefault();
        try{
    
            const config={
                headers:{
                    'Content-Type':'application/json'
                }
            }
            const {data}=await axios.post('/login',{email,password},config)
            localStorage.setItem('userInfo',JSON.stringify(data))
            userData.userInfo.setUser(data)
            navigate('/admin')
        }
        catch(error)
        {
            console.log(error.response.data)
            setErrorMessage(error.response.data);
        }
    }
    return (
        <div>
       <Container>
       <h1 className='text-center'>Login Form</h1>
       {
                                errorMessage!=="" &&
                                <div class="alert alert-danger" role="alert">
                                <p>{errorMessage}</p>
                            </div>
                            }
       <Form onSubmit={(e)=>handleSubmit(e)} >
  <Form.Group className="mb-3" controlId="formBasicEmail">
    <Form.Label>Email address</Form.Label>
    <Form.Control name="email" type="email" onChange={(e)=>setEmail(e.target.value)} value={email} placeholder="Enter email" />
  </Form.Group>

  <Form.Group className="mb-3" controlId="formBasicPassword">
    <Form.Label>Password</Form.Label>
    <Form.Control name="password" type="password" onChange={(e)=>setPassword(e.target.value)} value={password} placeholder="Password" />
  </Form.Group>
  <Button variant="primary" type="submit">
    Submit
  </Button>
  <p>Don't have an account?<Link to='/register'><span>sign up</span></Link></p>
</Form>
       </Container>
        </div>
    )
}

export default LoginScreen