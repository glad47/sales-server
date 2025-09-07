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
    tls: process.env.REDIS_TLS === 'true' ? true : undefined
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

async function verifyToken(req, res, next) {
  const raw = req.headers['authorization'];
  const token = raw?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token missing' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const status = await client.get(`token:${token}`);
    if (status !== 'valid') {
      return res.status(403).json({ success: false, message: 'حدث خطأ أثناء إرسال التصويت' });
    }

    // Mark token as used
    await client.set(`token:${token}`, 'used', { EX: 900 });
    next();
  } catch (err) {
    res.status(403).json({ success: false, message: 'Token invalid' });
  }
}







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
