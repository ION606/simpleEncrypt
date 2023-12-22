import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser';

const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));

const sidsToPubKeys = {};

app.get('/', async (req, res) => {
    res.sendFile('index.html', { root: '.' });
});

app.post('/newkey', async (req, res) => {
    try {
        const { sid, pkey } = req.headers;
        
        sidsToPubKeys[sid] = pkey;
        res.sendStatus(200);
    }
    catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

app.post('/getpubkey', async (req, res) => {
    // replace this with the other uid in the body later
    const { sid } = req.headers;
    if (!sid) res.sendStatus(404);
    else res.send(sidsToPubKeys[sid]);
});


app.listen(5000, () => { console.log("APP LISTENING ON PORT 5000!") });