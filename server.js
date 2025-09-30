const dotenv = require('dotenv');
console.log(process.env.NODE_ENV)
const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env';
console.log(envFile)
dotenv.config({ path: envFile });
const { v4 } = require('uuid');
const jwt = require('jsonwebtoken');

const http = require('http');
const WebSocket = require('ws');
const express = require('express');
const redis = require('redis');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app); // Create HTTP server
const wss = new WebSocket.Server({ server }); // Attach WebSocket to HTTP server

const client = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
    tls: process.env.REDIS_TLS === 'true' ? true : undefined
  }
});




(async () => {
  await client.connect().then(() => console.log('Connected to Redis')).catch((error) => {
  console.error('Failed to connect to Redis:', error);
    process.exit(1); // Exit with failure code
}); // connect once
  const subscriber = client.duplicate(); // duplicate after connection
  await subscriber.connect(); // connect the duplicate

  await subscriber.subscribe('offer-notification-channel', (message) => {
    const data = JSON.parse(message);
    wss.clients.forEach(client => {
        client.send(JSON.stringify(data));
    
    });
  });
})();



// Connect to Redis using TLS clustercfg.mydata.lsha4f.use1.cache.amazonaws.com









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



(async () => {
  const userId = `user:1120`;

  const exists = await client.exists(userId);
  if (!exists) {
    await client.hSet(userId, {
      user_id: 1120,
      username: APP_USERNAME,
      password: APP_PASSWORD,
      type: "root",
    });
    await client.lPush('users', userId);
    console.log('Root user created');
  } else {
    console.log('ℹRoot user already exists');
  }
})();





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


const findUserByUsername = async (targetUsername) => {
  try {
    // Step 1: Get all user IDs from the 'users' list
    const userIds = await client.lRange('users', 0, -1);

    // Step 2: Loop through each user ID and fetch their data
    for (const userId of userIds) {
      const userData = await client.hGetAll(userId);
      console.log(userData.username)
      if (userData.username === targetUsername) {
        return userData; // or return userId if you only need the ID
      }
    }

    console.log('No user found with username:', targetUsername);
    return null;
  } catch (err) {
    return null;
  }
};





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
    decoded = jwt.verify(token, SECRET_KEY, { ignoreExpiration: true });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      console.error('⏰ Token expired:', err.expiredAt);
      return res.status(401).json({ success: false, message: 'انتهت صلاحية التوكن' });
    }
    console.error('❌ Token verification failed:', err.message);
    return res.status(403).json({ success: false, message: 'توكن غير صالح' });
  }

  // Step 3: Validate role
  // if (decoded.role !== 'admin') {
  //   return res.status(403).json({ success: false, message: 'Unauthorized role' });
  // }

  // Step 4: Renew TTL
  await client.expire(`adminToken:${token}`, 7200); // 30 minutes

  req.admin = decoded;
  next();
}





app.post('/adminAuth', async (req, res) => {
  const { username, password } = req.body;

  const currentUser = await findUserByUsername(username)
  if(!currentUser){
        return res.status(401).json({ success: false, message: 'المستخدم غير موجود أو بياناته غير مكتملة' });
  }

  // Fetch user by username
  const stored = await client.hGetAll(`user:${currentUser.user_id}`);
  if (!stored.username || !stored.password) {
    return res.status(401).json({ success: false, message: 'المستخدم غير موجود أو بياناته غير مكتملة' });
  }

  if (username !== stored.username || password !== stored.password) {
    return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
  }

  // Include user type in token
  const token = jwt.sign({ role: stored.type, username }, SECRET_KEY, { expiresIn: '2h' });
  await client.set(`adminToken:${token}`, 'valid', { EX: 7200 });

  res.json({ success: true, token, type: stored.type });
});



// users

app.post('/add_user', verifyTAdminToken, async (req, res) => {
  const { username, password, type } = req.body;
  if (!username || !password  || !(type >= 0 && type <=3) ) {
    return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
  }

  const existingUser = await findUserByUsername(username);
  if (existingUser) {
    return res.status(960).json({ success: false, message: 'اسم المستخدم موجود بالفعل، لا يُسمح بالتكرار' });
  }

  const userId = Date.now();
  const key = `user:${userId}`;

  await client.hSet(key, {
    user_id: userId,
    username,
    password,
    type
  });

  await client.lPush('users', key);

  res.json({ success: true, userId });
});



app.get('/get_user/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const key = `user:${id}`;
  const exists = await client.exists(key);
  if (!exists) return res.status(10010).json({ success: false, message: 'المستخدم غير موجود' });

  const data = await client.hGetAll(key);
  res.json(data);
});


app.get('/get_current_user', verifyTAdminToken, async (req, res) => {
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  res.json(existingUser);
});



app.put('/update_user/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const { username, password, type } = req.body;

  const key = `user:${id}`;
  const exists = await client.exists(key);
  if (!exists) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  // Fetch the current user data
  const currentUser = await client.hGetAll(key);

  // Check if the new username belongs to another user
  const otherUser = await findUserByUsername(username);
  if (otherUser && otherUser.user_id !== id) {
    return res.status(960).json({ success: false, message: 'اسم المستخدم موجود بالفعل، لا يُسمح بالتكرار' });
  }

  // Update the user with new values or fallback to existing ones
  await client.hSet(key, {
    user_id: id,
    username: username || currentUser.username,
    password: password || currentUser.password,
    type: type || currentUser.type
  });

  res.json({ success: true, message: 'تم تحديث المستخدم بنجاح' });
});






app.delete('/delete_user/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const key = `user:${id}`;

  await client.del(key);
  await client.lRem('users', 0, key);

  res.json({ success: true });
});


app.get('/list_users', verifyTAdminToken, async (req, res) => {
  const keys = await client.lRange('users', 0, -1);
  const users = [];

  for (const key of keys) {
    const data = await client.hGetAll(key);
    users.push({ key: key.split(':')[1], ...data });
  }

  res.json(users);
});





// bill information 
app.post('/submit-quotation', verifyTAdminToken, async (req, res) => {
  const quotationData = req.body;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const bill_id = v4();
  const key = `quotation:${existingUser.user_id}:${bill_id}`;
  const time = Date.now()

  const dataToStore = {
    bill_id: bill_id,
    username: username,
    user_id: existingUser.user_id,
    timestamp:time,
    status: 0,
    ...quotationData,
  };

  try {
    await client.set(key, JSON.stringify(dataToStore));

    await client.publish('offer-notification-channel', JSON.stringify({
      bill_id: bill_id,
      username,
      type: "bill",
      companyName: quotationData.companyName,
      timestamp: time
    }));


    res.status(200).json({ message: 'Quotation stored successfully', key });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});


app.get('/notifications', verifyTAdminToken, async (req, res) => {
  const username = req.admin.username;
  const group = 'quotationGroup';
  const consumer = `user:${username}`;

  try {
    // Create group if not exists
    try {
      await client.xGroupCreate('quotationStream', group, '$', { MKSTREAM: true });
    } catch (e) {
      if (!e.message.includes('BUSYGROUP')) throw e;
    }

    // Read new messages for this user
    const entries = await client.xReadGroup(group, consumer, { key: 'quotationStream', id: '>' }, { COUNT: 10, BLOCK: 500 });

    const notifications = [];
    if (entries) {
      for (const entry of entries) {
        const stream = entry.name;
        const messages = entry.messages;

        for (const obj of messages) {
          notifications.push(obj.message);
          await client.xAck(stream, group, obj.id); // mark as read
        }
      }

    }

    res.status(200).json({ success: true, notifications });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


app.get('/offer-notifications', verifyTAdminToken, async (req, res) => {
  const username = req.admin.username;
  const group = 'offer-quotationGroup';
  const consumer = `user:${username}`;

  try {
    // Create group if not exists
    try {
      await client.xGroupCreate('offer-quotationStream', group, '$', { MKSTREAM: true });
    } catch (e) {
      if (!e.message.includes('BUSYGROUP')) throw e;
    }

    // Read new messages for this user
    const entries = await client.xReadGroup(group, consumer, { key: 'offer-quotationStream', id: '0' }, { COUNT: 10, BLOCK: 500 });

    const notifications = [];
    if (entries) {
      for (const entry of entries) {
        const stream = entry.name;
        const messages = entry.messages;

        for (const obj of messages) {
      
          notifications.push(obj.message);
          await client.xAck(stream, group, obj.id); // mark as read
        }
      }

    }

    res.status(200).json({ success: true, notifications });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


app.get('/search-quotations', verifyTAdminToken, async (req, res) => {
  const { username, companyName, status, date, page = 1, pageSize = 10 } = req.query;

  try {

  const username2 = req.admin.username;

  const existingUser = await findUserByUsername(username2);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

    const pattern = existingUser.type === 'root'
    ? 'quotation:*'
    : `quotation:${existingUser.user_id}:*`;
    const keys = await client.keys(pattern);

    const quotations = [];

    for (const key of keys) {
      const raw = await client.get(key);
      if (!raw) continue;

      const data = JSON.parse(raw);
      const statusMatch = status ? data.status == status : true;
      const matchesUsername = username ? data.username === username : true;
      const matchesCompany = companyName ? data.companyName?.includes(companyName) : true;
      const matchesDate = date ? new Date(data.timestamp).toISOString().slice(0, 10) === date : true;

      if (statusMatch && matchesUsername && matchesCompany && matchesDate) {
        quotations.push(data);
      }
    }

    quotations.sort((a, b) => Number(b.timestamp) - Number(a.timestamp));


    const total = quotations.length;
    const start = (page - 1) * pageSize;
    const paginated = quotations.slice(start, start + parseInt(pageSize));

    res.status(200).json({
      success: true,
      data: paginated,
      total,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    return res.status(200).json({
      success: true,
      data: [],
      total: 0,
      current: parseInt(page),
      pageSize: parseInt(pageSize),
      message: 'No offers found or error occurred'

      
    });
  }
});


app.get('/search-quotations-rec', verifyTAdminToken, async (req, res) => {
  const { username, companyName, status, date, page = 1, pageSize = 10 } = req.query;

  try {

  const username2 = req.admin.username;

  const existingUser = await findUserByUsername(username2);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

    const keys = await client.keys('quotation:*');

    const quotations = [];

    for (const key of keys) {
      const raw = await client.get(key);
      if (!raw) continue;

      const data = JSON.parse(raw);
      const statusMatch = status ? data.status == status : true;
      const matchesUsername = username ? data.username === username : true;
      const matchesCompany = companyName ? data.companyName?.includes(companyName) : true;
      const matchesDate = date ? new Date(data.timestamp).toISOString().slice(0, 10) === date : true;

      if (statusMatch && matchesUsername && matchesCompany && matchesDate) {
        quotations.push(data);
      }
    }

    quotations.sort((a, b) => Number(b.timestamp) - Number(a.timestamp));

    const total = quotations.length;
    const start = (page - 1) * pageSize;
    const paginated = quotations.slice(start, start + parseInt(pageSize));

    res.status(200).json({
      success: true,
      data: paginated,
      total,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    return res.status(200).json({
      success: true,
      data: [],
      total: 0,
      current: parseInt(page),
      pageSize: parseInt(pageSize),
      message: 'No offers found or error occurred'

      
    });
  }
});




app.put('/update-quotation/:bill_id', verifyTAdminToken, async (req, res) => {
  const { bill_id } = req.params;
  const updatedData = req.body;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const key = `quotation:${existingUser.user_id}:${bill_id}`;

  try {
    const existingQuotation = await client.get(key);
    if (!existingQuotation) {
      return res.status(404).json({ success: false, message: 'عرض السعر غير موجود' });
    }

    const parsedQuotation = JSON.parse(existingQuotation);

    const newData = {
      ...parsedQuotation,
      ...updatedData,
      timestamp: Date.now() // optional: update timestamp
    };

    await client.set(key, JSON.stringify(newData));
    res.status(200).json({ success: true, message: 'تم تحديث عرض السعر بنجاح', key });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});



app.put('/update-quotation-status/:bill_id', verifyTAdminToken, async (req, res) => {
  const { bill_id } = req.params;
  const { status } = req.body;
  const username = req.admin.username;

  if (typeof status !== 'number') {
    return res.status(400).json({ success: false, message: 'يجب أن تكون الحالة رقمًا صحيحًا' });
  }

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const key = `quotation:${existingUser.user_id}:${bill_id}`;

  try {
    const existingQuotation = await client.get(key);
    if (!existingQuotation) {
      return res.status(404).json({ success: false, message: 'عرض السعر غير موجود' });
    }

    const parsedQuotation = JSON.parse(existingQuotation);
    parsedQuotation.status = status;
    // parsedQuotation.timestamp = Date.now(); // optional

    await client.set(key, JSON.stringify(parsedQuotation));
    res.status(200).json({ success: true, message: 'تم تحديث حالة عرض السعر بنجاح', key });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});





app.get('/get_quotations', verifyTAdminToken, async (req, res) => {
  const {page = 1, pageSize = 10 } = req.query;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const pattern = existingUser.type === 'root'
    ? 'quotation:*'
    : `quotation:${existingUser.user_id}:*`;

  try {
    const allKeys = await client.keys(pattern);
    if (allKeys.length === 0) {
      return res.status(404).json({ success: false, message: 'لا توجد عروض أسعار' });
    }

    const sortedKeys = allKeys.sort((a, b) => {
      const ta = parseInt(a.split(':')[2]);
      const tb = parseInt(b.split(':')[2]);
      return tb - ta;
    });

    const start = (page - 1) * pageSize;
    const end = start + parseInt(pageSize);
    const paginatedKeys = sortedKeys.slice(start, end);

    const quotations = await Promise.all(paginatedKeys.map(key => client.get(key)));
    const parsed = quotations.map(q => JSON.parse(q));

    res.json({
      success: true,
      data: parsed,
      total: allKeys.length,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/get_quotations_by_status', verifyTAdminToken, async (req, res) => {
  const { page = 1, pageSize = 10, status } = req.query;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const pattern = existingUser.type === 'root'
    ? 'quotation:*'
    : `quotation:${existingUser.user_id}:*`;
  
 
  try {
    const allKeys = await client.keys(pattern);
    if (allKeys.length === 0) {
      return res.status(404).json({ success: false, message: 'لا توجد عروض أسعار' });
    }

    const quotations = await Promise.all(allKeys.map(key => client.get(key)));
    const parsed = quotations.map(q => JSON.parse(q));

    // ✅ Filter by status if provided
    const filtered = typeof status !== 'undefined'
      ? parsed.filter(q => q.status === parseInt(status))
      : parsed;

    const sorted = filtered.sort((a, b) => b.timestamp - a.timestamp);

    const start = (page - 1) * pageSize;
    const end = start + parseInt(pageSize);
    const paginated = sorted.slice(start, end);

    res.json({
      success: true,
      data: paginated,
      total: filtered.length,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




app.get('/get_quotation/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const key = `quotation:*:${id}`;
  // const exists = await client.exists(key);
  // if (!exists) {
  //   return res.status(404).json({ success: false, message: 'عرض السعر غير موجود' });
  // }

  const pattern = `quotation:*:${id}`;
  const [_, keys] = await client.scan(0, { MATCH: pattern, COUNT: '1' });
  console.log("*******")
  console.log(keys)

  // const quotation = await client.get(key);
  console.log("quotation")
  console.log(quotation)
  const parsed = JSON.parse(quotation);

 
  res.json({ success: true, data: parsed });
});



app.delete('/delete_quotation/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  // Restrict access to root users only
  if (existingUser.type !== 'root') {
    return res.status(403).json({ success: false, message: 'غير مصرح لك بحذف عرض السعر' });
  }

  // Find the key regardless of user_id
  const pattern = `quotation:*:${id}`;
  const matchingKeys = await client.keys(pattern);


  if (matchingKeys.length === 0) {
    return res.status(404).json({ success: false, message: 'عرض السعر غير موجود' });
  }

  try {
    await client.del(matchingKeys[0]); // delete the first match
    res.json({ success: true, message: 'تم حذف عرض السعر بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});





// offer information 
app.post('/submit-offer', verifyTAdminToken, async (req, res) => {
  const quotationData = req.body;
  const username = req.admin.username;

   const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const offer_id = v4();
  const key = `offer:${existingUser.user_id}:${offer_id}`;
  const time = Date.now()

  const dataToStore = {
    offer_id: offer_id,
    username: username,
    user_id: existingUser.user_id,
    timestamp:time,
    status: 0,
    ...quotationData,
  };

  try {
    await client.set(key, JSON.stringify(dataToStore));

    await client.publish('offer-notification-channel', JSON.stringify({
      offer_id: offer_id,
      username,
      type: "offer",
      timestamp: time
    }));


    
    res.status(200).json({ message: 'Quotation stored successfully', key });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/search-offers', verifyTAdminToken, async (req, res) => {
  const { username, date, status, page = 1, pageSize = 10 } = req.query;
  
  try {
    const username2 = req.admin.username;
    const existingUser = await findUserByUsername(username2);
    if (!existingUser) {
      return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
    }


      const pattern = existingUser.type === 'root'
    ? 'offer:*'
    : `offer:${existingUser.user_id}:*`;
    const keys = await client.keys(pattern);
    const offers = [];

    for (const key of keys) {
      const raw = await client.get(key);
      if (!raw) continue;

      const data = JSON.parse(raw);

      const statusMatch = status ? data.status == status : true
      const matchesUsername = username ? data.username === username : true;
      const matchesDate = date ? new Date(data.timestamp).toISOString().slice(0, 10) === date : true;

      if (statusMatch && matchesUsername && matchesDate) {
        offers.push(data);
      }
    }

    offers.sort((a, b) => Number(b.timestamp) - Number(a.timestamp));


    const total = offers.length;
    const start = (page - 1) * pageSize;
    const paginated = offers.slice(start, start + parseInt(pageSize));

    res.status(200).json({
      success: true,
      data: paginated,
      total,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    // res.status(500).json({ success: false, error: err.message });
    return res.status(200).json({
      success: true,
      data: [],
      total: 0,
      current: parseInt(page),
      pageSize: parseInt(pageSize),
      message: 'No offers found or error occurred'

      
    });
  }
});


app.get('/search-offers-rec', verifyTAdminToken, async (req, res) => {
  const { username, date, status, page = 1, pageSize = 10 } = req.query;
  
  try {
    const username2 = req.admin.username;
    const existingUser = await findUserByUsername(username2);
    if (!existingUser) {
      return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
    }

    const keys = await client.keys('offer:*');
    const offers = [];

    for (const key of keys) {
      const raw = await client.get(key);
      if (!raw) continue;

      const data = JSON.parse(raw);

      const statusMatch = status ? data.status == status : true
      const matchesUsername = username ? data.username === username : true;
      const matchesDate = date ? new Date(data.timestamp).toISOString().slice(0, 10) === date : true;

      if (statusMatch && matchesUsername && matchesDate) {
        offers.push(data);
      }
    }

    offers.sort((a, b) => Number(b.timestamp) - Number(a.timestamp));

    const total = offers.length;
    const start = (page - 1) * pageSize;
    const paginated = offers.slice(start, start + parseInt(pageSize));

    res.status(200).json({
      success: true,
      data: paginated,
      total,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    // res.status(500).json({ success: false, error: err.message });
    return res.status(200).json({
      success: true,
      data: [],
      total: 0,
      current: parseInt(page),
      pageSize: parseInt(pageSize),
      message: 'No offers found or error occurred'

      
    });
  }
});




app.put('/update-offer/:offer_id', verifyTAdminToken, async (req, res) => {
  const { offer_id } = req.params;
  const updatedData = req.body;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const key = `offer:${existingUser.user_id}:${offer_id}`;

  try {
    const existingQuotation = await client.get(key);
    if (!existingQuotation) {
      return res.status(404).json({ success: false, message: 'عرض غير موجود' });
    }

    const parsedQuotation = JSON.parse(existingQuotation);

    const newData = {
      ...parsedQuotation,
      ...updatedData,
      timestamp: Date.now() // optional: update timestamp
    };

    await client.set(key, JSON.stringify(newData));
    res.status(200).json({ success: true, message: 'تم تحديث العرض بنجاح', key });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});


app.put('/update-offer-status/:offer_id', verifyTAdminToken, async (req, res) => {
  const { offer_id } = req.params;
  const { status } = req.body;
  const username = req.admin.username;

  if (typeof status !== 'number') {
    return res.status(400).json({ success: false, message: 'يجب أن تكون الحالة رقمًا صحيحًا' });
  }

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const key = `offer:${existingUser.user_id}:${offer_id}`;

  try {
    const existingQuotation = await client.get(key);
    if (!existingQuotation) {
      return res.status(404).json({ success: false, message: 'العرض غير موجود' });
    }

    const parsedQuotation = JSON.parse(existingQuotation);
    parsedQuotation.status = status;
    // parsedQuotation.timestamp = Date.now(); // optional

    await client.set(key, JSON.stringify(parsedQuotation));
    res.status(200).json({ success: true, message: 'تم تحديث حالة عرض السعر بنجاح', key });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});




app.get('/get_offers', verifyTAdminToken, async (req, res) => {
  const {page = 1, pageSize = 10 } = req.query;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const pattern = existingUser.type === 'root'
    ? 'offer:*'
    : `offer:${existingUser.user_id}:*`;

  try {
    const allKeys = await client.keys(pattern);
    if (allKeys.length === 0) {
      return res.status(404).json({ success: false, message: 'لا توجد عروض' });
    }

    const sortedKeys = allKeys.sort((a, b) => {
      const ta = parseInt(a.split(':')[2]);
      const tb = parseInt(b.split(':')[2]);
      return tb - ta;
    });

    const start = (page - 1) * pageSize;
    const end = start + parseInt(pageSize);
    const paginatedKeys = sortedKeys.slice(start, end);

    const quotations = await Promise.all(paginatedKeys.map(key => client.get(key)));
    const parsed = quotations.map(q => JSON.parse(q));

    res.json({
      success: true,
      data: parsed,
      total: allKeys.length,
      current: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.get('/get_offer/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  const pattern = `offer:*:${id}`;
  console.log(pattern)
  const [_, keys] = await client.scan(0, { MATCH: pattern, COUNT: 1 });

  if (keys.length === 0) {
    return res.status(404).json({ success: false, message: 'عرض غير موجود' });
  }

  const key = keys[0];
  const quotation = await client.get(key);

  if (!quotation) {
    return res.status(404).json({ success: false, message: 'المحتوى غير موجود لهذا العرض' });
  }

  let parsed;
  try {
    parsed = JSON.parse(quotation);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'خطأ في قراءة بيانات العرض' });
  }

  res.json({ success: true, data: parsed });
});



app.delete('/delete_offer/:id', verifyTAdminToken, async (req, res) => {
  const { id } = req.params;
  const username = req.admin.username;

  const existingUser = await findUserByUsername(username);
  if (!existingUser) {
    return res.status(959).json({ success: false, message: 'المستخدم غير موجود' });
  }

  // Restrict access to root users only
  if (existingUser.type !== 'root') {
    return res.status(403).json({ success: false, message: 'غير مصرح لك بحذف العرض' });
  }

  // Find the key regardless of user_id
  const pattern = `offer:*:${id}`;
  const matchingKeys = await client.keys(pattern);


  if (matchingKeys.length === 0) {
    return res.status(404).json({ success: false, message: 'عرض السعر غير موجود' });
  }

  try {
    await client.del(matchingKeys[0]); // delete the first match
    res.json({ success: true, message: 'تم حذف عرض السعر بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});






















// Endpoint to cast a vote
// app.post('/vote', verifyToken, async (req, res) => {
//   const { name, phone, tiktok } = req.body;
//   if (!name || !phone || !tiktok) {
//     return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
//   }

//   const voteId = `vote:${phone}:${tiktok}`;
//   await client.hSet(voteId, { name, phone, tiktok });
//   await client.lPush('votes', voteId);
//   res.json({ success: true, message: 'تم تسجيل التصويت بنجاح' });
// });



// Endpoint to get current vote counts
app.get('/results', verifyTAdminToken, async (req, res) => {
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


// Express route
app.get('/voting-stats',verifyTAdminToken, async (req, res) => {
  try {
    
    const votes = await client.lRange('votes', 0, -1); // total votes
   

    const keys = await client.keys('token:*');
    

    const pending = keys.length

    res.json({
      votes: votes.length,
      pending,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});


app.post('/reset-competition', verifyTAdminToken, async (req, res) => {
  try {
    await client.del('votes');
    const keys = await client.keys('token:*');
    for (const key of keys) {
      await client.del(key);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset competition' });
  }
});


app.get('/pick-winner', verifyTAdminToken, async (req, res) => {
  try {
    const votes = await client.lRange('votes', 0, -1);
    if (votes.length === 0) return res.status(404).json({ error: 'No votes found' });

    const randomIndex = Math.floor(Math.random() * votes.length);
    const key = votes[randomIndex];
    const winner = await client.hGetAll(key);

    res.json(winner);
  } catch (err) {
    res.status(500).json({ error: 'Failed to pick winner' });
  }
});





app.post('/auth', async (req, res) => {

  const token = jwt.sign({ username: "Glad" }, SECRET_KEY, { expiresIn: '15m' });
  await client.set(`token:${token}`, 'valid', { EX: 900 }); // 15m expiry
  res.json({ token });

});



const PORT = process.env.PORT || 8888;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
