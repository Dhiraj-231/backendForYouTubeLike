import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import router from "./src/routes/user.routes.js";
const app = express();

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}));

app.use(express.json({ limit: "100Kb" }));
app.use(express.urlencoded({ extended: true, limit: "100Kb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use("/api/v1/user", router)
export default app;