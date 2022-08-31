const express = require('express')
const session = require('express-session')
const bcrypt = require('bcrypt')
const {pool} = require('./db')
const jwt = require('jsonwebtoken')
// const bodyParser = require('body-parser')

let tokenList = {}

const app = express()

app.use(express.json())
app.use(session({
    secret: 'secretkey',
     
}))

app.get('/', (req, res) => {
    res.send("Welcome to the BAlink test from Rahamim Glauberg")
})

app.post('/refreshToken', (req, res)=> {
    let {email, refreshToken} = req.body
    let refreshed = false
    let message = ''
    let tokens = {"accessToken": null, "refreshToken":null}
    if (tokenList.hasOwnProperty(refreshToken)) {
        tokens.accessToken = jwt.sign({ email: email }, "accessSecret", {expiresIn: "2m",});
        tokens.refreshToken = jwt.sign({ email: email }, "refreshSecret", {expiresIn: "10m",});

        tokenList[tokens.refreshToken] = tokens

        refreshed = true
        message = 'Token refreshed'
    } else {
        message = 'Invalid token'
    }

    res.status(200).json({"refreshed": refreshed, "message": message, "accessToken": tokens.accessToken, "refreshToken": tokens.refreshToken})
})

app.post('/api/signin', async(req, res) => {
    let {firstname, lastname, email, password} = req.body

    let message = ''
    let registered = false
    let tokens = {"accessToken": null, "refreshToken":null}
    const passwordFormat = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$")

    if (!passwordFormat.test(password)) {
        message = "Password doesn't match required format"
        res.status(200).json({"registered": registered, "message": message, "accessToken": tokens.accessToken, "refreshToken": tokens.refreshToken})
    }

    let checkUser = await pool.query('SELECT * FROM users WHERE email = $1' ,[email])
    if (checkUser.rows.length > 0) {
        message = "A user account already exists for this email"
    } else {
        let addUser = await pool.query('INSERT INTO users (firstname, lastname, email, password) VALUES ($1, $2, $3, $4) RETURNING id', [firstname, lastname, email, await bcrypt.hash(password, 10)])
        console.log("addUser", addUser);
        if (addUser.rows.length > 0) {
            message = "You are now registered"
            tokens.accessToken = jwt.sign({ email: email }, "accessSecret", {expiresIn: "2m",});
            tokens.refreshToken = jwt.sign({ email: email }, "refreshSecret", {expiresIn: "10m",});

            tokenList[tokens.refreshToken] = tokens
        }
    }
    res.status(200).json({"registered": registered, "message": message, "accessToken": tokens.accessToken, "refreshToken": tokens.refreshToken})
})

app.post('/api/login', async (req, res) => {
    let {email, password} = req.body
    let message = ''
    let loggedin = false
    let tokens = {"accessToken": null, "refreshToken":null}

    let connectUser = await pool.query('SELECT * FROM users WHERE email = $1', [email])
    if (connectUser.rows.length > 0) {
        let user = connectUser.rows[0]
        let match = await bcrypt.compare(password, user.password)
        if (match) {
            message = "Welcome back"
            loggedin = true
            tokens.accessToken = jwt.sign({ email: email }, "accessSecret", {expiresIn: "2m",});
            tokens.refreshToken = jwt.sign({ email: email }, "refreshSecret", {expiresIn: "10m",});

            tokenList[tokens.refreshToken] = tokens
        } else {
            message = "Wrong password"
        }
    } else {
        message = "No user found"
    }
    
    res.status(200).json({"loggedin": loggedin, "message": message, "accessToken": tokens.accessToken, "refreshToken": tokens.refreshToken})
})

app.listen(3000, () => console.log('BAlink test running on port 3000'))