import * as express from "express";

const app = express();
app.use(express.json());

app.post("/calculate", (req, res) => {
    const formula = req.body.formula;

    // ❌ Dangerous use of eval (Code Injection)
    const result = eval(formula);

    res.send({ result });
});

app.post("/deserialize", (req, res) => {
    const data = req.body.data;

    // ❌ Insecure deserialization
    const obj = JSON.parse(data);

    res.send(obj);
});

app.listen(4000, () => {
    console.log("App running on port 4000");
});