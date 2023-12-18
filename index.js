import app from "./app.js";
import databaseConnect from "./src/db/databaseConnect.js";
import dotenv from "dotenv";
dotenv.config({ path: "./.env" });
databaseConnect();
app.get("/", (req, res) => {
    res.send("<h2>This is example server </h2>");
})

app.listen(process.env.PORT || 5000, () => {
    console.log(`Server is started at port:${process.env.PORT || 5000}`);
})