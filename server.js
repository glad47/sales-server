const dotenv = require('dotenv');
console.log(process.env.NODE_ENV)
const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env';
console.log(envFile)
dotenv.config({ path: envFile });

const jwt = require('jsonwebtoken');


const express = require('express');
const redis = require('redis');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());




// Connect to Redis using TLS clustercfg.mydata.lsha4f.use1.cache.amazonaws.com




const client = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
    tls: process.env.REDIS_TLS === 'true' ? {} : undefined
  }
});


client.connect().then(() => console.log('Connected to Redis')).catch((error) => {
  console.error('❌ Failed to connect to Redis:', err);
    process.exit(1); // Exit with failure code
});


// Validate critical env vars
if (!process.env.REDIS_HOST || !process.env.JWT_SECRET) {
  throw new Error('❌ Missing critical environment variables: REDIS_HOST or JWT_SECRET');
}
const SECRET_KEY = process.env.JWT_SECRET 

const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;

if (!APP_USERNAME || !APP_PASSWORD) {
  throw new Error('❌ Missing APP_USERNAME or APP_PASSWORD in environment config');
}




await client.hSet('admin', {
  username: APP_USERNAME,
  password: APP_PASSWORD
});





async function verifyToken(req, res, next) {
  const raw = req.headers['authorization'];
  const token = raw?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token missing' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);

    const status = await client.get(`token:${token}`);
    if (status !== 'valid') {
      return res.status(403).json({ success: false, message: 'Token already used or invalid' });
    }

    // Mark token as used
    await client.set(`token:${token}`, 'used', { EX: 900 });

    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ success: false, message: 'Token invalid' });
  }
}


async function verifyTAdminToken(req, res, next) {
  const raw = req.headers['authorization'];
  const token = raw?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, message: 'Token missing' });
  }

  // Step 1: Check Redis for token existence
  const exists = await client.exists(`adminToken:${token}`);
  if (!exists) {
    return res.status(403).json({ success: false, message: 'Admin token not registered' });
  }

  // Step 2: Verify JWT
  let decoded;
  try {
    decoded = jwt.verify(token, SECRET_KEY);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      console.error('⏰ Token expired:', err.expiredAt);
      return res.status(401).json({ success: false, message: 'انتهت صلاحية التوكن' });
    }
    console.error('❌ Token verification failed:', err.message);
    return res.status(403).json({ success: false, message: 'توكن غير صالح' });
  }

  // Step 3: Validate role
  if (decoded.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized role' });
  }

  // Step 4: Renew TTL
  await client.expire(`adminToken:${token}`, 1800); // 30 minutes

  req.admin = decoded;
  next();
}





app.post('/adminAuth', async (req, res) => {
  const { username, password } = req.body;

  const stored = await client.hGetAll('admin');
  if (!stored.username || !stored.password) {
    return res.status(500).json({ success: false, message: 'Admin credentials not initialized' });
  }

  if (username !== stored.username || password !== stored.password) {
    return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
  }

  const token = jwt.sign({ role: 'admin', username }, SECRET_KEY, { expiresIn: '30m' });
  await client.set(`adminToken:${token}`, 'valid', { EX: 1800 }); // 30m expiry

  res.json({ success: true, token });
});








// Endpoint to cast a vote
app.post('/vote', verifyToken, async (req, res) => {
  const { name, phone, tiktok } = req.body;
  if (!name || !phone || !tiktok) {
    return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
  }

  const voteId = `vote:${phone}:${tiktok}`;
  await client.hSet(voteId, { name, phone, tiktok });
  await client.lPush('votes', voteId);
  res.json({ success: true, message: 'تم تسجيل التصويت بنجاح' });
});


// Endpoint to get current vote counts
app.get('/results', verifyToken, async (req, res) => {
  if (!client.isOpen) {
    return res.status(503).json({ success: false, message: 'Redis غير متصل حالياً' });
  }

  try {
    const voteKeys = await client.lRange('votes', 0, -1);
    const allVotes = {};

    for (const key of voteKeys) {
      const voteData = await client.hGetAll(key);
      allVotes[key] = voteData;
    }

    res.json(allVotes);
  } catch (err) {
    console.error('❌ Error fetching results:', err);
    res.status(500).json({ success: false, message: 'خطأ في جلب النتائج' });
  }
});



app.post('/auth', async (req, res) => {

  const token = jwt.sign({ username: "Glad" }, SECRET_KEY, { expiresIn: '15m' });
  await client.set(`token:${token}`, 'valid', { EX: 900 }); // 15m expiry
  res.json({ token });

});



const PORT = process.env.PORT || 8888;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
