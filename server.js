const express = require('express')
const dotenv = require('dotenv')
const cors = require('cors')
const { v4: uuidv4 } = require('uuid')
const bcrypt = require('bcrypt')
const cloudinary = require('./utlis/cloudinary')
const multer = require('multer')
const mongoose = require('mongoose')
const Member = require('./models/memberModel')
const path = require('path')
const jwt = require('jsonwebtoken')
const User = require('./models/userModel')
const Committee = require('./models/committeeModel')
const Event = require('./models/eventModel')
const DsrgEvent = require('./models/dsrgEventModel')
const Blog = require('./models/blogModel')
const Faculty = require('./models/facultyModel')
const AutoPassword = require('./models/autoPasswordModel')
const { isAuth, isAdmin } = require('./middlewares/authMiddleware')
const inMemoryStorage = multer.memoryStorage()
const { Readable } = require('stream')
const nodemailer = require('nodemailer')
const PORT = process.env.port || 5000
dotenv.config()

const app = express()
app.use(express.json())

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('mongoose is connected'))
  .catch((err) => console.log(err))

app.use(cors())
app.use(express.static(path.join(__dirname, '/public')))
app.use(express.static(path.join(__dirname, './client/build')))

const upload = multer({ storage: inMemoryStorage })

const DatauriParser = require('datauri/parser')
const parser = new DatauriParser()

///routes

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization

  if (authHeader) {
    const token = authHeader.split(' ')[1]

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res
          .status(403)
          .send({ success: false, message: 'not valid token' })
      }

      req.user = user
      next()
    })
  } else {
    return res.status(401).send({ success: false, message: 'not valid token' })
  }
}

// Define a route to check if a JWT is valid
app.get('/api/checkjwt', authenticateJWT, (req, res) => {
  return res.json({ success: true, message: 'JWT is valid' })
})

app.post('/login', async (req, res) => {
  //const {username,password}=req.body;
  const { membershipId, password } = req.body
  const user = await User.findOne({ membershipId })
  if (!user) {
    return res
      .status(401)
      .send('This user is not registered or no membershipId')
  } else {
    const isMatched = await bcrypt.compare(password, user.password)
    if (isMatched) {
      const generatedToken = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET,
        {
          expiresIn: '2h',
        },
      )
      return res.json({
        _id: user._id,
        username: user.username,
        isAdmin: user.isAdmin,
        token: generatedToken,
      })
    } else {
      return res.status(401).send('Membership Id or password is wrong')
    }
  }
})

app.get('/getAutoPasswords', isAuth, isAdmin, async (req, res) => {
  const getAllAutoPass = await AutoPassword.find({}).sort({ uname: 1 })
  const getAllMembers = await Member.find({}).sort({ username: 1 })
  res.status(200).send({ getAllAutoPass, getAllMembers })
})
app.post('/register', async (req, res) => {
  const { username, password } = req.body

  const user = await User.findOne({ username })
  if (user) {
    return res.status(401).send('This user is already registered')
  } else {
    const hashedPassword = await bcrypt.hash(password, 10)
    const newuser = new User({
      username,
      password: hashedPassword,
      isAdmin: false,
    })
    await newuser
      .save()
      .then((user) => {
        return res.send(user)
      })
      .catch((err) => {
        return res.status(401).send('Server error')
      })
  }
})

function sendMail(req, res, email, membershipId, username, userEmail) {
  var Transport = nodemailer.createTransport({
    /*host: "localhost", // hostname
      secure: false, // use SSL
      port: 3000, */
    service: 'Gmail',
    auth: {
      user: process.env.NODEMAILUSER,
      pass: process.env.NODEMAILPASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
  })
  let mailOptions
  mailOptions = {
    from: 'IDSRG ' + process.env.NODEMAILUSER,
    to: email,
    subject: 'Forgot Password(idsrg)',
    text: 'I have forgot my password',
    html: `<h4>I have forgot my password.Please give me a new password</h4>
        <p>Membership Id:${membershipId}</p><p>Username:${username}</p>
        <p>Email:${userEmail}</p>`,
  }
  console.log(mailOptions)
  Transport.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error)
      return res.status(500).send({success:false,message:"Server error",error})
    } else {
      console.log('Message sent ' + info.response)
      return res.status(200).send({success:true,message:"Request has sent to admin successfully",info:info.response})
    }
  })
}

app.post('/api/changeForgotPasswordRequest',(req, res) => {
  try {
    const { membershipId, username, userEmail } = req.body
    if (membershipId != '' && username != '' && userEmail != '')
      sendMail(
        req,
        res,
        'retaw84957@duiter.com',
        membershipId,
        username,
        userEmail,
      )
    else return res.status(401).send({ message: 'All fields are required' })
  } catch (error) {
    return res.status(401).json({ message: error.message })
  }
})

app.get('/api/members', async (req, res) => {
  try {
    const members = await Member.find({})
    return res.status(200).send(members)
  } catch (error) {
    return res.status(401).json({ message: error })
  }
})

app.get('/api/committee', async (req, res) => {
  try {
    const committeMembers = await Committee.find({})
    return res.status(200).send(committeMembers)
  } catch (error) {
    return res.status(401).send('committee members not found')
  }
})

async function getDataSortedBySerial() {
  try {
    const sortedData = await Faculty.find().sort({ faculty_order: 1 })
    return sortedData
  } catch (err) {
    console.error(err)
    return null
  }
}

app.get('/api/faculties', async (req, res) => {
  try {
    const faculties = await getDataSortedBySerial()
    return res.status(200).send(faculties)
  } catch (error) {
    return res.status(401).send('error in fecthing faculties')
  }
})

app.post('/api/faculties', isAuth, isAdmin, async (req, res) => {
  const {
    username,
    name,
    teaching_designation,
    dept,
    section,
    session,
  } = req.body

  if (
    !(username === '') &&
    !(name === '') &&
    !(teaching_designation === '') &&
    !(dept === '') &&
    !(session === '')
  ) {
    const isMemberExist = await Faculty.findOne({ username })
    if (isMemberExist) {
      return res
        .status(401)
        .send({ message: 'This user is already registered', success: false })
    } else {
      //const hashedPassword=await bcrypt.hash(password,10);
      const newFaculty = new Faculty({
        username,
        name,
        teaching_designation,
        dept,
        section: 'faculty_members',
        session,
      })
      await newFaculty
        .save()
        .then((faculty) => {
          return res.status(200).send({ faculty, success: true })
        })
        .catch((err) => {
          console.log(err)
          return res
            .status(500)
            .send({ message: 'Server error', success: false })
        })
    }
  } else {
    return res
      .status(401)
      .send({ message: '* fields are required', success: false })
  }
})

app.get('/api/events', async (req, res) => {
  try {
    // const events=await Event.find({})
    const events = await DsrgEvent.find({})

    return res.status(200).send(events)
  } catch (error) {
    return res.status(401).send('Error in fetching events')
  }
})

app.get('/api/blogs', async (req, res) => {
  try {
    const blogs = await Blog.find({})
    return res.status(200).send(blogs)
  } catch (error) {
    return res.status(401).send('Error in fetching blogs')
  }
})

app.post('/api/publications/:username', isAuth, async (req, res) => {
  try {
    const { pname, authors } = req.body
    const member = await Member.findOne({ username: req.params.username })
    if (member) {
      const tempPubs = member.reseachers_and_publications
      tempPubs.push({
        paper_name: pname,
        authors: authors,
      })
      member.reseachers_and_publications = tempPubs

      await member
        .save()
        .then((m) => {
          return res.status(200).send({ member: m, success: true })
        })
        .catch((err) => {
          console.log(err)
          return res
            .status(500)
            .send({ message: 'Server error', success: false })
        })
    } else return res.status(404).send('not found')
  } catch (error) {
    return res.status(401).json({ message: error })
  }
})

app.put('/api/changePassword', isAuth, async (req, res) => {
  User.findById(req.user._id, async (err, user) => {
    if (err || !user) {
      return res.status(401).send('user not found')
    }

    // Check if the current password is correct
    if (!(await bcrypt.compare(req.body.currentPassword, user.password))) {
      return res.status(401).send('Incorrect Current Password')
    }

    // Hash the new password
    const hash = await bcrypt.hash(req.body.newPassword, 10)

    // Update the user document with the new password
    user.password = hash
    await user.save((err, updatedUser) => {
      if (err) {
        return res.status(400).send('Failed to update password')
      }
      const generatedToken = jwt.sign(
        { id: updatedUser._id },
        process.env.JWT_SECRET,
        {
          expiresIn: '10d',
        },
      )
      return res.json({
        _id: updatedUser._id,
        username: updatedUser.username,
        isAdmin: updatedUser.isAdmin,
        token: generatedToken,
      })
    })
  })
})
app.post('/api/skills/:username', isAuth, async (req, res) => {
  try {
    const { skills } = req.body
    const member = await Member.findOne({ username: req.params.username })
    if (member) {
      const tempSkills = member.skills
      let newArray = []
      let elements = skills.split(',')

      for (let i = 0; i < elements.length; i++) {
        newArray.push(elements[i])
      }

      let mergedArray = []

      for (let i = 0; i < tempSkills.length; i++) {
        if (!mergedArray.includes(tempSkills[i])) {
          mergedArray.push(tempSkills[i])
        }
      }

      for (let i = 0; i < newArray.length; i++) {
        if (!mergedArray.includes(newArray[i])) {
          mergedArray.push(newArray[i])
        }
      }

      member.skills = mergedArray

      await member
        .save()
        .then((m) => {
          return res.status(200).send({ member: m, success: true })
        })
        .catch((err) => {
          console.log(err)
          return res
            .status(500)
            .send({ message: 'Server error', success: false })
        })
    } else return res.status(404).send('not found')
  } catch (error) {
    return res.status(401).json({ message: error })
  }
})

app.get('/api/events/:id', async (req, res) => {
  try {
    // const event=await Event.findById(req.params.id)

    const event = await DsrgEvent.findById(req.params.id)
    return res.status(200).send(event)
  } catch (error) {
    return res.status(401).send('Error in fetching event')
  }
})

app.get('/api/blogs/:id', async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id)
    return res.status(200).send(blog)
  } catch (error) {
    return res.status(401).send('Error in fetching blog')
  }
})

app.get('/api/members/:username', async (req, res) => {
  try {
    const member = await Member.findOne({ username: req.params.username })
    if (member) return res.status(200).send(member)
    else return res.status(404).send('not found')
  } catch (error) {
    return res.status(401).json({ message: error })
  }
})

app.get('/api/editMember/:id', isAuth, isAdmin, async (req, res) => {
  await Member.findOne({ _id: req.params.id })
    .then((member) => res.status(200).send({ member, success: true }))
    .catch((err) =>
      res.status(404).send({ message: 'member not found', success: false }),
    )
})

app.get('/api/editFaculty/:id', isAuth, isAdmin, async (req, res) => {
  await Faculty.findOne({ _id: req.params.id })
    .then((member) => res.status(200).send({ member, success: true }))
    .catch((err) =>
      res.status(404).send({ message: 'member not found', success: false }),
    )
})

app.post(
  '/api/events',
  isAuth,
  isAdmin,
  upload.array('event_image'),
  async (req, res) => {
   
    try {
      const results = await Promise.all(
        req.files.map(async (file) => {
          const extName = path.extname(file.originalname).toString()
          const file64 = parser.format(extName, file.buffer)
          const result = await cloudinary.uploader.upload(file64.content, {
            uploads: 'products',
            public_id: `${Date.now()}`,
            resource_type: 'image',
            timeOut: 120000,
          })
          return result
        }),
      )
      // res.send(results);

      const imagePath = []
      results.map((rs) => imagePath.push(rs.secure_url))

      const { title, description } = req.body
      // const newEvent=new Event({
      const newEvent = new DsrgEvent({
        image: imagePath,
        title,
        description,
        date: new Date().toISOString(),
      })
      await newEvent
        .save()
        .then((event) => {
          return res.status(200).send({ event, success: true })
        })
        .catch((err) => {
          console.log(err)
          return res
            .status(500)
            .send({ message: 'Server error', success: false })
        })
    } catch (error) {
      console.log(error)
      res.status(500).send(error)
    }
  },
)

app.post(
  '/api/blogs',
  isAuth,
  upload.single('blog_image'),
  async (req, res) => {
   
    let imagePath = ''
    if (req.file) {
      const extName = path.extname(req.file.originalname).toString()
      const file64 = parser.format(extName, req.file.buffer)
      const result = await cloudinary.uploader.upload(file64.content, {
        uploads: 'products',
        // width: 300,
        // crop: "scale"
        public_id: `${Date.now()}`,
        resource_type: 'auto',
      })
      imagePath = result.secure_url
    }

    const { username, title, description, name } = req.body
    const newBlog = new Blog({
      username,
      name,
      image: imagePath,
      title,
      description,
      date: new Date().toISOString(),
    })
    await newBlog
      .save()
      .then((blog) => {
        return res.status(200).send({ blog, success: true })
      })
      .catch((err) => {
        console.log(err)
        return res.status(500).send({ message: 'Server error', success: false })
      })
  },
)

app.put(
  '/api/editMember/:id',
  isAuth,
  isAdmin,
  upload.single('image'),
  async (req, res) => {
    try {
      const member = await Member.findById(req.params.id)
      if (member) {
        const { name, email, phone } = req.body

        let imagePath = ''
        if (req.file) {
          const extName = path.extname(req.file.originalname).toString()
          const file64 = parser.format(extName, req.file.buffer)
          const result = await cloudinary.uploader.upload(file64.content, {
            uploads: 'products',
            // width: 300,
            // crop: "scale"
            public_id: `${Date.now()}`,
            resource_type: 'auto',
          })

          // imagePath = String('/' + req.file.destination.split('/').slice(1) + '/' + req.file.filename);
          imagePath = result.secure_url
        } else imagePath = member.profileImg

        if (!(name === '') && !(email === '') && !(phone === '')) {
          const isMemberExist = await Member.findOne({ email })
          if (isMemberExist && email !== member.email) {
            return res
              .status(401)
              .send({
                message: 'This member is already registered',
                success: false,
              })
          } else {
            member.name = req.body.name || member.name
            member.email = req.body.email || member.email
            member.phone = req.body.phone || member.phone
            member.profileImg = imagePath
            member.field_of_interest =
              req.body.field_of_interest || member.field_of_interest
            member.description = req.body.description || member.description
            member.membershipId = req.body.membershipId || member.membershipId
            const updatedMember = await member.save()
            const finduser = await User.findOne({ username: member.username })
            finduser.membershipId = member.membershipId
            const updatedUser = await finduser.save()
            return res
              .status(200)
              .send({ member: updatedMember, success: true })
          }
        } else {
          return res
            .status(401)
            .send({ message: '* fields are required', success: false })
        }
      } else {
        return res
          .status(401)
          .send({ message: 'Member not found', success: false })
      }
    } catch (error) {
      console.log(error)
      return res.status(500).send({ message: 'Server error', success: false })
    }
  },
)

app.put(
  '/api/editFaculty/:id',
  isAuth,
  isAdmin,
  upload.single('image'),
  async (req, res) => {
    try {
      const faculty = await Faculty.findById(req.params.id)
      if (faculty) {
        const {
          username,
          name,
          teaching_designation,
          dept,
          section,
          session,
        } = req.body

        let imagePath = ''
        if (req.file) {
          const extName = path.extname(req.file.originalname).toString()
          const file64 = parser.format(extName, req.file.buffer)
          const result = await cloudinary.uploader.upload(file64.content, {
            uploads: 'products',
            // width: 300,
            // crop: "scale"
            public_id: `${Date.now()}`,
            resource_type: 'auto',
          })

          // imagePath = String('/' + req.file.destination.split('/').slice(1) + '/' + req.file.filename);
          imagePath = result.secure_url
        } else imagePath = faculty.image

        if (
          !(username === '') &&
          !(name === '') &&
          !(teaching_designation === '') &&
          !(dept === '') &&
          !(section === '') &&
          !(session === '')
        ) {
          const isMemberExist = await Faculty.findOne({ username })
          if (!isMemberExist) {
            return res
              .status(401)
              .send({ message: 'This user is not registered', success: false })
          } else {
            //faculty.username=req.body.username||faculty.username
            faculty.name = req.body.name || faculty.name
            faculty.image = imagePath
            faculty.teaching_designation =
              req.body.teaching_designation || faculty.teaching_designation
            faculty.dept = req.body.dept || faculty.dept
            faculty.section = req.body.section || faculty.section
            faculty.session = req.body.session || faculty.session
            const updatedFaculty = await faculty.save()
            return res
              .status(200)
              .send({ member: updatedFaculty, success: true })
          }
        } else {
          return res
            .status(401)
            .send({ message: '* fields are required', success: false })
        }
      } else {
        return res
          .status(401)
          .send({ message: 'Member not found', success: false })
      }
    } catch (error) {
      console.log(error)
      return res.status(500).send({ message: 'Server error', success: false })
    }
  },
)

app.post('/api/members', isAuth, isAdmin, async (req, res) => {
  const {
    username,
    name,
    email,
    phone,
    field_of_interest,
    jobs,
    description,
  } = req.body

  if (
    !(name === '') &&
    !(username === '') &&
    !(email === '') &&
    !(phone === '')
  ) {
    const isMemberExist = await Member.findOne({ username })
    if (isMemberExist) {
      return res
        .status(401)
        .send({ message: 'This user is already registered', success: false })
    } else {
      //const hashedPassword=await bcrypt.hash(password,10);
      const newMember = new Member({
        username,
        name,
        email,
        phone,
        field_of_interest,
        jobs,
        description,
      })
      await newMember
        .save()
        .then(async (member) => {
          const password = Math.floor(
            10000000 + Math.random() * 90000000,
          ).toString()
          const hashedPassword = await bcrypt.hash(password, 10)
          const newPass = new AutoPassword({
            uname: username,
            pass: password,
          })
          await newPass
            .save()
            .then(async (autopass) => {
              console.log(autopass)
              const newuser = new User({
                username: username,
                password: hashedPassword,
                isAdmin: false,
              })
              await newuser
                .save()
                .then((user) => {
                  console.log(user)
                })
                .catch((err) => {
                  console.log('Server error')
                })
            })
            .catch((err) => {
              console.log('Server error')
            })

          return res.status(200).send({ member, success: true })
        })
        .catch((err) => {
          console.log(err)
          return res
            .status(500)
            .send({ message: 'Server error', success: false })
        })
    }
  } else {
    return res
      .status(401)
      .send({ message: '* fields are required', success: false })
  }
})

//admin will change user password
app.post('/api/changeForgetPassword', isAuth, isAdmin, async (req, res) => {
  try {
    const { username, membershipId } = req.body

    if (username=="" || membershipId=="") {
      return res
        .status(401)
        .send({ message: 'All * fields are required', success: false })
    }

    const isUserExist = await User.findOne({ username })
    if (!isUserExist) {
      return res
        .status(401)
        .send({ message: 'This user is not registered', success: false })
    }

    if (isUserExist.membershipId !== membershipId) {
      return res
        .status(401)
        .send({ message: 'This membership is not found', success: false })
    }

    const password = Math.floor(10000000 + Math.random() * 90000000).toString()
    const hashedPassword = await bcrypt.hash(password, 10)

    let findSavedAutoPassword = await AutoPassword.findOne({ uname: username })
    findSavedAutoPassword.pass = password
    await findSavedAutoPassword.save()

    isUserExist.password = hashedPassword
    await isUserExist.save()

    return res.status(200).send({ message: 'Password changed successfully(auto password added)', success: true })
  } catch (error) {
    console.log(error)
    return res
      .status(500)
      .send({ message: 'Internal Server Error', success: false })
  }
})

app.put('/api/jobs/:id', isAuth, async (req, res) => {
  try {
    const member = await Member.findById(req.params.id)
    if (member) {
      const {
        company,
        startDate,
        endDate,
        designation,
        jobDescription,
      } = req.body
      const tempJobs = member.jobs
      tempJobs.push({ ...req.body })
      member.jobs = tempJobs
      const updatedMember = await member.save()
      return res.status(200).send({ member: updatedMember, success: true })
    } else {
      return res
        .status(401)
        .send({ message: 'Member not found', success: false })
    }
  } catch (error) {
    console.log(error)
    return res.status(500).send({ message: 'Server error', success: false })
  }
})

app.get('/api/deleteMember/:id', isAuth, isAdmin, async (req, res) => {
  try {
    const deletedMember = await Member.findByIdAndRemove(req.params.id)
    return res.status(200).send(deletedMember)
  } catch (error) {
    return res.status(401).send('User not found')
  }
})

app.get('/api/deleteFaculty/:id', isAuth, isAdmin, async (req, res) => {
  try {
    const deletedFaculty = await Faculty.findByIdAndRemove(req.params.id)
    return res.status(200).send(deletedFaculty)
  } catch (error) {
    return res.status(401).send('Faculty not found')
  }
})

app.get('*', function (req, res) {
  res.sendFile(path.join(__dirname, './client/build/index.html'))
})

app.listen(PORT, (err) => {
  if (err) console.log(err)
  else console.log(`Server is running at ${PORT}`)
})
