const router = require("express").Router()
const bcrypt = require("bcryptjs")
const Users = require("../users/users-model.js")

router.post("/register", (req, res) => {

  let creds = req.body
  const rounds = process.env.HASH_ROUNDS || 4
  const hash = bcrypt.hashSync(creds.password, rounds)

  creds.password = hash

  Users.add(creds)
    .then((saved) => {
      res.status(201).json({ data: saved })
    })
    .catch((error) => {
      res.status(500).json({ error: error.message })
    })
})

router.post("/login", (req, res) => {

    const { username, password } = req.body
    
    Users.findBy({ username }).then(user => {
        if (user[0] && bcrypt.compareSync(password, user[0].password)) {
            //store the session to the db
            //product a cookie and store session id inside the cookie
            //send back the cookie with the session id to the client 
            req.session.loggedIn = true
            req.session.username = user[0].username
            res.status(200).json({message: "welcome!", session: req.session})
        } else {
            res.status(401).json({message: 'invalid credentials'})
        }
    })
    .catch(error => res.status(500).json({error: error.message}))
})

router.post("/logout", (req, res) => {
    res.status(204).end()
})

module.exports = router


