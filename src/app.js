import express from "express"
import cors from "cors"
// kind of crud operations from cookies 
import cookieParser from "cookie-parser"

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))


// to set limit of accepting data 
app.use(express.json({limit: "16kb"}))

// urlencoded for making code understand that it is a url in request not a json so handle accordingly :) 
//extended not needed but it is for adding objects in objects
app.use(express.urlencoded({extended: true, limit: "16kb"}))

//for assets
app.use(express.static("public"))
app.use(cookieParser())

//routes import
import userRouter from "./routes/user.routes.js"

//routes declaration
// using middleware (app.use) instead of app.get since we separated everything now
app.use("/users", userRouter)

// http:/localhost:8000/users/register    -> this is how it will get carried forward 

export {app}