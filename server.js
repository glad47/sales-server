const express = require('express');
const redis = require('redis');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to Redis using TLS 
const client = redis.createClient({
  socket: {
    host: 'clustercfg.mydata.lsha4f.use1.cache.amazonaws.com',
    port: 6379,
    tls: true
  }
});

client.connect().then(() => console.log('Connected to Redis')).catch(console.error);

// Endpoint to cast a vote
app.post('/vote', async (req, res) => {
  const { name, phone, tiktok } = req.body;

  if (!name || !phone || !tiktok) {
    res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
  }

  const voteId = `vote:${phone}:${tiktok}`;
  await client.hSet(voteId, { name, phone, tiktok });
  await client.lPush('votes', voteId);

  res.json({ success: true, message: 'تم تسجيل التصويت بنجاح' });

});

// Endpoint to get current vote counts
app.get('/results', async (req, res) => {
  const voteKeys = await client.lRange('votes', 0, -1);
  const allVotes = {};

  for (const key of voteKeys) {
    const voteData = await client.hGetAll(key);
    allVotes[key] = voteData;
  }

  res.json(allVotes);
});


const PORT = process.env.PORT || 8888;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
