import express from "express";
import path from "path";
import cookieParser from "cookie-parser";
import logger from "morgan";


import indexRouter from "./routes/index.js";
import usersRouter from "./routes/users.js";

const app = express();

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
// app.use(express.static(path.join(import.meta.dirname, "public")));
app.use(express.static(path.join(import.meta.dirname, "routes")));

app.use("/", indexRouter);
app.use("/users", usersRouter);

export default app;