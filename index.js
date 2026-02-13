const express = require('express');
const app = express();
const cors = require('cors');
require('dotenv').config();
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion } = require('mongodb');

// middleware
app.use(cors({
    origin: process.env.SITE_URL,
    credentials: true,
}));
app.use(express.json());

const uri = process.env.MONGO_URL;

if (!uri) {
    console.error("Error: MONGO_URL is not defined in the .env file.");
    process.exit(1);
}

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server
        // await client.connect();
        const FinTrackDB = client.db("FinTrackDB");
        const usersCollection = FinTrackDB.collection("users");

        // users related api
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'User already exists' });
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (error) {
        console.error("Failed to connect to MongoDB", error);
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Fintrack Server is running!')
});

app.listen(port, () => {
    console.log(`Fintrack Server is running on port ${port}`)
});
