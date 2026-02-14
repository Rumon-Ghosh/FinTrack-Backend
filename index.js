const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// middleware
app.use(cors({
    origin: [process.env.SITE_URL || 'http://localhost:5173'],
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

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

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req?.cookies?.token;
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Unauthorized access' });
        }
        req.user = decoded;
        next();
    });
};

// Middleware to verify Admin
const verifyAdmin = async (req, res, next) => {
    const email = req.user.email;
    const query = { email: email };
    const user = await client.db("FinTrackDB").collection("users").findOne(query);
    const isAdmin = user?.role === 'admin';
    if (!isAdmin) {
        return res.status(403).send({ message: 'Forbidden access' });
    }
    next();
};

async function run() {
    try {
        // Connect the client to the server
        await client.connect();
        const FinTrackDB = client.db("FinTrackDB");
        const usersCollection = FinTrackDB.collection("users");
        const transactionsCollection = FinTrackDB.collection("transactions");
        const categoriesCollection = FinTrackDB.collection("categories");
        const goalsCollection = FinTrackDB.collection("goals");
        const tipsCollection = FinTrackDB.collection("tips");

        // Auth related API
        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            }).send({ success: true });
        });

        app.post('/logout', async (req, res) => {
            res.clearCookie('token', {
                maxAge: 0,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            }).send({ success: true });
        });

        // Use this to get the currently logged in user
        app.get('/me', verifyToken, async (req, res) => {
            const email = req.user.email;
            const query = { email: email };
            const result = await usersCollection.findOne(query);
            if (result) {
                res.send({ success: true, user: result });
            } else {
                res.status(404).send({ success: false, message: 'User not found' });
            }
        });

        // users related api
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'User already exists', insertedId: null });
            }

            // Hash password
            user.password = await bcrypt.hash(user.password, 10);
            user.createdAt = new Date().toISOString();

            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        app.post('/login', async (req, res) => {
            const { email, password } = req.body;
            const user = await usersCollection.findOne({ email });
            if (!user) {
                return res.send({ success: false, message: 'User not found' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.send({ success: false, message: 'Invalid credentials' });
            }

            // Create JWT Token
            const token = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            }).send({ success: true, user: { fullname: user.fullname, email: user.email, photo: user.photo, role: user.role } });
        });

        // Admin Only: Users Management
        app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const search = req.query.search || "";
            const skip = (page - 1) * limit;

            const query = search ? {
                $or: [
                    { fullname: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } }
                ]
            } : {};

            const total = await usersCollection.countDocuments(query);
            const users = await usersCollection.find(query)
                .skip(skip)
                .limit(limit)
                .toArray();

            res.send({
                users,
                total,
                totalPages: Math.ceil(total / limit),
                currentPage: page
            });
        });

        app.patch('/users/role/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { role } = req.body;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: { role: role }
            };
            const result = await usersCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await usersCollection.deleteOne(query);
            res.send(result);
        });

        app.patch('/users/profile', verifyToken, async (req, res) => {
            const email = req.user.email;
            const { fullname, photo } = req.body;
            const filter = { email: email };
            const updatedDoc = {
                $set: {
                    fullname: fullname,
                    photo: photo
                }
            };
            const result = await usersCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        // Categories API
        app.get('/categories', async (req, res) => {
            const result = await categoriesCollection.find().toArray();
            res.send(result);
        });

        app.post('/categories', verifyToken, verifyAdmin, async (req, res) => {
            const category = req.body;
            const result = await categoriesCollection.insertOne(category);
            res.send(result);
        });

        app.delete('/categories/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await categoriesCollection.deleteOne(query);
            res.send(result);
        });

        // Admin Stats API
        app.get('/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
            const usersCount = await usersCollection.countDocuments({ role: { $ne: "admin" } });
            const transactionsCount = await transactionsCollection.countDocuments();

            const amountResult = await transactionsCollection.aggregate([
                { $group: { _id: null, total: { $sum: "$amount" } } }
            ]).toArray();
            const totalAmount = amountResult[0]?.total || 0;

            // Monthly breakdown for charts
            const currentYear = new Date().getFullYear();
            const monthlyStats = await transactionsCollection.aggregate([
                {
                    $match: {
                        date: { $regex: `^${currentYear}` }
                    }
                },
                {
                    $group: {
                        _id: { $month: { $dateFromString: { dateString: "$date" } } },
                        count: { $sum: 1 },
                        total: { $sum: "$amount" }
                    }
                },
                { $sort: { "_id": 1 } }
            ]).toArray();

            res.send({
                usersCount,
                transactionsCount,
                totalAmount,
                monthlyStats
            });
        });

        app.get('/transactions/all', verifyToken, async (req, res) => {
            const email = req.user.email;
            const transactions = await transactionsCollection.find({ userEmail: email })
                .sort({ date: -1 })
                .toArray();
            res.send(transactions);
        });

        // Transactions API with Pagination and Filtering
        app.get('/transactions', verifyToken, async (req, res) => {
            const email = req.user.email;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const type = req.query.type || 'all';
            const category = req.query.category || 'all';
            const search = req.query.search || '';
            const sortBy = req.query.sortBy || 'date';
            const order = req.query.order === 'asc' ? 1 : -1;
            const skip = (page - 1) * limit;

            let query = { userEmail: email };

            if (type !== 'all') query.type = type;
            if (category !== 'all') query.category = category;
            if (search) {
                query.$or = [
                    { note: { $regex: search, $options: 'i' } },
                    { category: { $regex: search, $options: 'i' } }
                ];
            }

            const total = await transactionsCollection.countDocuments(query);
            const transactions = await transactionsCollection.find(query)
                .sort({ [sortBy]: order })
                .skip(skip)
                .limit(limit)
                .toArray();

            // Aggregated stats for the user (always based on all user transactions)
            const statsPipeline = [
                { $match: { userEmail: email } },
                {
                    $group: {
                        _id: null,
                        totalIncome: {
                            $sum: { $cond: [{ $eq: ["$type", "income"] }, "$amount", 0] }
                        },
                        totalExpense: {
                            $sum: { $cond: [{ $eq: ["$type", "expense"] }, "$amount", 0] }
                        }
                    }
                }
            ];
            const statsResult = await transactionsCollection.aggregate(statsPipeline).toArray();
            const stats = statsResult[0] || { totalIncome: 0, totalExpense: 0 };

            res.send({
                transactions,
                total,
                totalPages: Math.ceil(total / limit),
                currentPage: page,
                stats
            });
        });

        // Transaction post API
        app.post('/transactions', verifyToken, async (req, res) => {
            const transaction = req.body;
            transaction.userEmail = req.user.email;
            transaction.amount = parseFloat(transaction.amount);
            transaction.date = transaction.date || new Date().toISOString();
            const result = await transactionsCollection.insertOne(transaction);
            res.send(result);
        });

        app.patch('/transactions/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id), userEmail: req.user.email };
            const updatedDoc = {
                $set: {
                    ...req.body,
                    amount: parseFloat(req.body.amount || 0)
                }
            };
            const result = await transactionsCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        app.delete('/transactions/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id), userEmail: req.user.email };
            const result = await transactionsCollection.deleteOne(query);
            res.send(result);
        });

        // Goals API 
        app.get('/goals', verifyToken, async (req, res) => {
            const query = { userEmail: req.user.email };
            const result = await goalsCollection.find(query).toArray();
            res.send(result);
        });

        app.post('/goals', verifyToken, async (req, res) => {
            const goal = req.body;
            goal.userEmail = req.user.email;
            const result = await goalsCollection.insertOne(goal);
            res.send(result);
        });

        app.patch('/goals/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id), userEmail: req.user.email };
            const result = await goalsCollection.updateOne(filter, { $set: req.body });
            res.send(result);
        });

        app.delete('/goals/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id), userEmail: req.user.email };
            const result = await goalsCollection.deleteOne(query);
            res.send(result);
        });

        // Financial Tips API
        app.get('/tips', async (req, res) => {
            const result = await tipsCollection.find().sort({ date: -1 }).toArray();
            res.send(result);
        });

        app.post('/tips', verifyToken, verifyAdmin, async (req, res) => {
            const tip = req.body;
            tip.date = new Date().toISOString();
            const result = await tipsCollection.insertOne(tip);
            res.send(result);
        });

        app.patch('/tips/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    title: req.body.title,
                    description: req.body.description,
                    category: req.body.category
                }
            };
            const result = await tipsCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        app.delete('/tips/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await tipsCollection.deleteOne(query);
            res.send(result);
        });

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (error) {
        console.error("Failed to connect to MongoDB", error);
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('FinTrack Server is running!')
});

app.listen(port, () => {
    console.log(`FibTrack Server is running on port ${port}`)
});
