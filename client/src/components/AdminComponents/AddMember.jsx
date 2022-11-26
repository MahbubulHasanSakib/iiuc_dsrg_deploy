import React, { useState } from 'react'
import { Form } from 'react-bootstrap'
import axios from 'axios'
const AddMember = () => {
    const [memberInfo, setMemberInfo] = useState({
        name:"",
        email: "",
        phone: "",
        field_of_interest: "",
        description: "",
        jobs: []
    })

    const [errorMessage, setErrorMessage] = useState('')
    const [successMessage, setSuccessMessage] = useState('')
    const handleSubmit = async (e) => {

        const user=localStorage.getItem('userInfo')?JSON.parse(localStorage.getItem('userInfo')):null

        e.preventDefault()

        try {
            const config = {
                headers: {
                    'Content-Type': 'application/json',
                     Authorization:`Bearer ${user.token}`
                }
            }
            const { data } = await axios.post('/api/members', memberInfo, config)
            console.log(data);
            if (data.success) {
                setErrorMessage('')
                setSuccessMessage('Member added successfully')
            }
        }
        catch (error) {
            console.log(error.response);
            setSuccessMessage('')
            setErrorMessage(error.response.data.message);
        }

    }
    const handleChange = (e) => {
        const key = e.target.name;
        const value = e.target.value;
        setMemberInfo({ ...memberInfo, [key]: value })
    }

    return (
        <div class="container register">
            <div class="row">
                <div class="col-md-3 register-left">
                </div>
                <div class="col-md-9 register-right">

                    <div class="tab-content" id="myTabContent">
                        <Form onSubmit={handleSubmit}>
                            <div class="tab-pane fade show active" id="home" role="tabpanel" aria-labelledby="home-tab">
                                <h3 class="register-heading">Add a member</h3>
                                <div class="row register-form">
                                    {
                                        errorMessage!=="" &&
                                        <div class="alert alert-danger" role="alert">
                                        <p>{errorMessage}</p>
                                    </div>
                                    }
                                  {
                                    successMessage!=="" &&
                                    <div class="alert alert-success" role="alert">
                                    <p>{successMessage}</p>
                                </div>
                                  }

                                    <div class="col-md-6">
                                        
                                        <div class="form-group">
                                            <input type="text"
                                                onChange={handleChange} name="name" class="form-control" placeholder="Full Name" value={memberInfo.name} />
                                        </div>
                                        <div class="form-group">
                                            <input type="email" onChange={handleChange} name="email" class="form-control" placeholder="Email *" value={memberInfo.email} />
                                        </div>
                                        <div class="form-group">
                                            <input type="text" onChange={handleChange} name="phone" class="form-control" placeholder="Phone *" value={memberInfo.phone} />
                                        </div>
                                        <div class="form-group">
                                            <input type="text" name="field_of_interest" onChange={handleChange} class="form-control" placeholder="Field of interest" value={memberInfo.field_of_interest} />
                                        </div>
                                    </div>
                                    <div class="col-md-6">

                                        <div class="form-group">
                                            <textarea placeholder="Description" onChange={handleChange} name="description" value={memberInfo.description} rows={10} cols={40}></textarea>
                                        </div>

                                        <input type="submit" class="btnRegister" value="Register" />
                                    </div>
                                </div>
                            </div>

                        </Form>
                    </div>
                </div>
            </div>

        </div>
    )
}

export default AddMember