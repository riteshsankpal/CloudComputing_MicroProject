/* =====================================================================
   Smart Cloud Complaint Management System - Backend
   Express + MongoDB (Mongoose) + GridFS + JWT auth
   All configuration comes from environment variables (.env).
   ====================================================================== */
require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const multer = require('multer');

const {
  MONGODB_URI = 'mongodb://localhost:27017/complaint_db',
  JWT_SECRET = 'dev-secret-change-me',
  PORT = 3000,
  ADMIN_NAME = 'Super Admin',
  ADMIN_EMAIL = 'admin@campus.edu',
  ADMIN_PASSWORD = 'Admin@123',
  COOKIE_SECURE = 'false',
  ENABLE_DEMO_ACCOUNTS = 'true',
  DNS_SERVERS = ''
} = process.env;

/* Optional: force DNS servers (helps mongodb+srv on networks where the
   default resolver cannot answer SRV queries). Example: DNS_SERVERS=1.1.1.1 */
if (DNS_SERVERS) {
  require('dns').setServers(DNS_SERVERS.split(',').map((s) => s.trim()).filter(Boolean));
}

if (JWT_SECRET === 'dev-secret-change-me') {
  console.warn('[warn] JWT_SECRET is not set in .env - using an insecure default.');
}

/* ------------------------------------------------------------------ */
/* Models                                                              */
/* ------------------------------------------------------------------ */
const { Schema, model, Types } = mongoose;

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['student', 'department', 'admin'], default: 'student' },
    department: { type: Types.ObjectId, ref: 'Department', default: null },
    rollNo: { type: String, default: '' },
    phone: { type: String, default: '' },
    active: { type: Boolean, default: true }
  },
  { timestamps: true }
);

const departmentSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    category: { type: String, required: true, lowercase: true, trim: true },
    description: { type: String, default: '' },
    email: { type: String, default: '' },
    active: { type: Boolean, default: true }
  },
  { timestamps: true }
);

const commentSchema = new Schema(
  {
    byName: String,
    byRole: String,
    text: { type: String, required: true },
    at: { type: Date, default: Date.now }
  },
  { _id: true }
);

const timelineSchema = new Schema(
  {
    action: String,
    note: String,
    byName: String,
    byRole: String,
    at: { type: Date, default: Date.now }
  },
  { _id: true }
);

const complaintSchema = new Schema(
  {
    ticketId: { type: String, unique: true, index: true },
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    category: { type: String, default: 'general', lowercase: true },
    priority: { type: String, enum: ['high', 'medium', 'low'], default: 'medium' },
    location: { type: String, default: '' },
    status: {
      type: String,
      enum: ['submitted', 'assigned', 'in_progress', 'resolved', 'closed', 'escalated'],
      default: 'submitted'
    },
    student: { type: Types.ObjectId, ref: 'User', required: true, index: true },
    department: { type: Types.ObjectId, ref: 'Department', default: null, index: true },

    imageFileId: { type: Types.ObjectId, default: null },
    imageFilename: { type: String, default: '' },
    imageMimeType: { type: String, default: '' },
    imageSize: { type: Number, default: 0 },

    slaHours: { type: Number, default: 24 },
    slaDueAt: { type: Date, default: null },
    slaBreached: { type: Boolean, default: false, index: true },
    slaBreachedAt: { type: Date, default: null },

    escalated: { type: Boolean, default: false },
    escalatedReason: { type: String, default: '' },
    resolutionRemarks: { type: String, default: '' },
    rating: { type: Number, default: 0 },

    autoCategory: { type: Boolean, default: false },
    autoPriority: { type: Boolean, default: false },
    autoAssigned: { type: Boolean, default: false },

    resolvedAt: { type: Date, default: null },
    closedAt: { type: Date, default: null },

    comments: [commentSchema],
    timeline: [timelineSchema]
  },
  { timestamps: true }
);

const notificationSchema = new Schema(
  {
    user: { type: Types.ObjectId, ref: 'User', required: true, index: true },
    title: String,
    message: String,
    type: { type: String, default: 'info' },
    complaint: { type: Types.ObjectId, ref: 'Complaint', default: null },
    ticketId: { type: String, default: '' },
    read: { type: Boolean, default: false }
  },
  { timestamps: true }
);

const activityLogSchema = new Schema(
  {
    action: String,
    detail: String,
    actorName: String,
    actorRole: String,
    ticketId: { type: String, default: '' }
  },
  { timestamps: true }
);

const User = model('User', userSchema);
const Department = model('Department', departmentSchema);
const Complaint = model('Complaint', complaintSchema);
const Notification = model('Notification', notificationSchema);
const ActivityLog = model('ActivityLog', activityLogSchema);

/* ------------------------------------------------------------------ */
/* Smart rules: category / priority / auto-assignment                  */
/* ------------------------------------------------------------------ */
const CATEGORY_KEYWORDS = {
  electrical: ['fan', 'light', 'lights', 'electricity', 'electric', 'switch', 'socket', 'bulb',
    'power', 'wiring', 'wire', 'ac ', 'air conditioner', 'cooler', 'short circuit', 'spark',
    'sparking', 'tube', 'inverter', 'panel', 'shock', 'voltage', 'fuse'],
  it: ['wifi', 'wi-fi', 'internet', 'network', 'lan', 'router', 'server', 'computer',
    'computer lab', 'laptop', 'software', 'printer', 'system', 'bandwidth', 'cyber',
    'website', 'portal', 'login', 'projector', 'online', 'ethernet', 'cctv'],
  plumbing: ['water', 'pipe', 'pipeline', 'leak', 'leakage', 'leaking', 'tap', 'faucet',
    'toilet', 'washroom', 'bathroom', 'drain', 'drainage', 'flush', 'sink', 'sewer',
    'tank', 'commode', 'clog', 'plumber'],
  housekeeping: ['garbage', 'dirty', 'dusting', 'cleaning', 'clean', 'dust', 'trash',
    'sweep', 'sweeper', 'stain', 'smell', 'stink', 'pest', 'rat', 'rats', 'cockroach',
    'litter', 'bin', 'waste', 'mop', 'dirty floor', 'unhygienic', 'hygiene'],
  furniture: ['chair', 'chairs', 'table', 'tables', 'bench', 'benches', 'desk',
    'cupboard', 'almirah', 'shelf', 'shelves', 'door', 'window', 'blackboard',
    'broken seat', 'stool', 'wardrobe', 'drawer', 'carpenter', 'furniture', 'partition'],
  general: ['wall', 'floor', 'paint', 'painting', 'construction', 'roof', 'ceiling',
    'gate', 'parking', 'sign', 'board', 'pathway', 'gardening', 'grass', 'noise']
};

const CATEGORY_LABELS = {
  electrical: 'Electrical',
  it: 'IT & Network',
  plumbing: 'Plumbing',
  housekeeping: 'Housekeeping',
  furniture: 'Furniture',
  general: 'General Maintenance'
};

const HIGH_KEYWORDS = ['danger', 'dangerous', 'urgent', 'urgently', 'immediately', 'security',
  'theft', 'stolen', 'shock', 'electric shock', 'accident', 'injury', 'injured', 'fire',
  'emergency', 'critical', 'collapsed', 'collapse', 'harassment', 'harass', 'leak',
  'leaking', 'sparking', 'broken glass', 'short circuit', 'flood', 'blocked'];
const LOW_KEYWORDS = ['minor', 'small issue', 'slight', 'cosmetic', 'whenever', 'not urgent',
  'low priority', 'suggestion', 'nice to have', 'little problem', 'scratch', 'dust in corner'];

function countHits(text, words) {
  let n = 0;
  for (const w of words) {
    const idx = text.indexOf(w);
    if (idx === -1) continue;
    n += 1;
    // count extra occurrences
    let from = idx + w.length;
    while (text.indexOf(w, from) !== -1) { n += 1; from += w.length; }
  }
  return n;
}

function detectCategory(text) {
  const t = ' ' + String(text || '').toLowerCase().replace(/[^a-z0-9\s-]/g, ' ') + ' ';
  let best = null;
  let bestScore = 0;
  for (const [cat, words] of Object.entries(CATEGORY_KEYWORDS)) {
    const score = countHits(t, words);
    if (score > bestScore) { bestScore = score; best = cat; }
  }
  if (!best) return { category: 'general', auto: false };
  return { category: best, auto: true };
}

function recommendPriority(text) {
  const t = String(text || '').toLowerCase();
  if (countHits(t, HIGH_KEYWORDS) > 0) return { priority: 'high', auto: true };
  if (countHits(t, LOW_KEYWORDS) > 0) return { priority: 'low', auto: true };
  return { priority: 'medium', auto: true };
}

const SLA_HOURS = { high: 6, medium: 24, low: 72 };

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* Safe cast: accepts ObjectId / 24-char hex string / populated doc ({_id}).
   Returns null for anything else (names, numbers-as-strings, junk, undefined). */
function toObjectId(value) {
  if (value == null || value === '') return null;
  if (value instanceof Types.ObjectId) return value;
  if (typeof value === 'object') return value._id != null ? toObjectId(value._id) : null;
  const str = String(value);
  return mongoose.isValidObjectId(str) ? new Types.ObjectId(str) : null;
}

function signToken(user) {
  const departmentId =
    user.department == null || user.department === ''
      ? null
      : String(user.department._id || user.department);
  return jwt.sign(
    { id: user._id.toString(), role: user.role, name: user.name, department: departmentId },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function setAuthCookie(res, token) {
  res.cookie('ccms_token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE === 'true',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

async function auth(req, res, next) {
  const header = req.headers.authorization;
  const token = (header && header.startsWith('Bearer ') && header.slice(7)) || req.cookies?.ccms_token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Session expired, please login again' });
  }
  try {
    /* Never trust the department stored inside the JWT: it can be stale if the
       department was re-created or re-assigned after login. Read it fresh. */
    const u = await User.findById(req.user.id).select('role department email active');
    if (!u || !u.active) return res.status(401).json({ error: 'Account not found or deactivated' });
    req.user.role = u.role;
    let deptId = toObjectId(u.department);
    if (u.role === 'department') {
      let dept = deptId ? await Department.findById(deptId).select('_id') : null;
      if (!dept) {
        /* Self-heal: link the account to the department that has the same email */
        dept = await Department.findOne({ email: u.email });
        if (dept) { u.department = dept._id; await u.save(); }
      }
      deptId = dept ? dept._id : null;
    }
    req.user.department = deptId ? deptId.toHexString() : null;
    next();
  } catch (e) {
    next(e);
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission to do this' });
    }
    next();
  };
}

async function logActivity({ action, detail, user, ticketId = '' }) {
  try {
    await ActivityLog.create({
      action,
      detail,
      actorName: user ? user.name : 'System',
      actorRole: user ? user.role : 'system',
      ticketId
    });
  } catch (e) { console.error('activity log failed', e.message); }
}

async function notify(users, data) {
  try {
    const ids = (Array.isArray(users) ? users : [users]).filter(Boolean);
    if (!ids.length) return;
    await Notification.insertMany(ids.map((u) => ({ ...data, user: u })));
  } catch (e) { console.error('notify failed', e.message); }
}

async function notifyRole(role, data, departmentId = null) {
  const filter = { role, active: true };
  if (departmentId) filter.department = departmentId;
  const users = await User.find(filter).select('_id');
  await notify(users.map((u) => u._id), data);
}

function pushTimeline(complaint, action, user, note = '') {
  complaint.timeline.push({
    action,
    note,
    byName: user.name,
    byRole: user.role,
    at: new Date()
  });
}

async function makeTicketId() {
  for (let i = 0; i < 5; i++) {
    const id = 'CMP-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const exists = await Complaint.exists({ ticketId: id });
    if (!exists) return id;
  }
  return 'CMP-' + Date.now().toString(36).toUpperCase();
}

const STATUS_LABEL = {
  submitted: 'Submitted',
  assigned: 'Assigned',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  closed: 'Closed',
  escalated: 'Escalated'
};

const ALLOWED_TRANSITIONS = {
  submitted: ['assigned'],
  assigned: ['in_progress', 'resolved', 'escalated'],
  in_progress: ['resolved', 'escalated'],
  resolved: ['closed', 'in_progress'],
  escalated: ['in_progress', 'resolved', 'closed'],
  closed: ['in_progress']
};

/* Compare a complaint's department (ObjectId OR populated doc) with a user's department id. */
function sameDept(complaintDept, userDept) {
  const a = toObjectId(complaintDept);
  const b = toObjectId(userDept);
  return !!(a && b && a.equals(b));
}

function canAccess(user, complaint) {
  if (user.role === 'admin') return true;
  if (user.role === 'student') return String(complaint.student?._id || complaint.student) === user.id;
  if (user.role === 'department') {
    return sameDept(complaint.department, user.department);
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* App                                                                 */
/* ------------------------------------------------------------------ */
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

let bucket = null;
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpe?g|gif|webp|bmp|svg\+xml)$/.test(file.mimetype)) return cb(null, true);
    cb(new Error('Only image files are allowed'));
  }
});

/* ------------------------------ Auth ------------------------------ */
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, password, rollNo = '', phone = '' } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const exists = await User.findOne({ email: String(email).toLowerCase() });
  if (exists) return res.status(400).json({ error: 'An account with this email already exists' });

  const hash = await bcrypt.hash(password, 10);
  const user = await User.create({
    name, email, password: hash, role: 'student', rollNo, phone
  });
  setAuthCookie(res, signToken(user));
  await logActivity({ action: 'register', detail: `Student "${name}" registered`, user: { name, role: 'student' } });
  res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role, rollNo: user.rollNo } });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const user = await User.findOne({ email: String(email).toLowerCase() }).select('+password').populate('department', 'name category');
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  if (!user.active) return res.status(403).json({ error: 'Your account has been deactivated. Contact the administrator.' });

  setAuthCookie(res, signToken(user));
  await logActivity({ action: 'login', detail: `${user.name} (${user.role}) logged in`, user });
  res.json({
    user: {
      id: user._id, name: user.name, email: user.email, role: user.role,
      rollNo: user.rollNo, phone: user.phone,
      department: user.department ? { id: user.department._id, name: user.department.name, category: user.department.category } : null
    }
  });
}));

/* Demo accounts are only advertised when ENABLE_DEMO_ACCOUNTS=true */
app.get('/api/auth/demo-accounts', (req, res) => {
  if (ENABLE_DEMO_ACCOUNTS !== 'true') return res.json({ accounts: [] });
  res.json({
    accounts: [
      { role: 'admin', label: 'Super Admin', email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
      { role: 'department', label: 'Electrical Dept', email: 'electrical@campus.edu', password: 'Demo@123' },
      { role: 'student', label: 'Student', email: 'student@campus.edu', password: 'Demo@123' }
    ]
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('ccms_token');
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, wrap(async (req, res) => {
  const user = await User.findById(req.user.id).populate('department', 'name category');
  if (!user || !user.active) return res.status(401).json({ error: 'Account not found or deactivated' });
  if (user.role === 'department' && !user.department && req.user.department) {
    await user.populate('department', 'name category');
  }
  res.json({
    user: {
      id: user._id, name: user.name, email: user.email, role: user.role,
      rollNo: user.rollNo, phone: user.phone, createdAt: user.createdAt,
      department: user.department ? { id: user.department._id, name: user.department.name, category: user.department.category } : null
    }
  });
}));

app.put('/api/profile', auth, wrap(async (req, res) => {
  const { name, phone, rollNo, currentPassword, newPassword } = req.body || {};
  const user = await User.findById(req.user.id).select('+password');
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (name) user.name = String(name).trim();
  if (phone !== undefined) user.phone = phone;
  if (rollNo !== undefined && user.role === 'student') user.rollNo = rollNo;
  if (newPassword) {
    if (!currentPassword) return res.status(400).json({ error: 'Current password is required' });
    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok) return res.status(400).json({ error: 'Current password is incorrect' });
    if (String(newPassword).length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    user.password = await bcrypt.hash(newPassword, 10);
  }
  await user.save();
  await logActivity({ action: 'profile_update', detail: `${user.name} updated their profile`, user });
  res.json({ ok: true, message: 'Profile updated successfully' });
}));

/* --------------------------- Departments -------------------------- */
app.get('/api/departments', auth, wrap(async (req, res) => {
  const filter = req.query.all === '1' && req.user.role === 'admin' ? {} : { active: true };
  const deps = await Department.find(filter).sort({ name: 1 });
  res.json({
    departments: deps.map((d) => ({
      id: d._id, name: d.name, category: d.category, description: d.description,
      email: d.email, active: d.active,
      label: CATEGORY_LABELS[d.category] || d.name
    })),
    categories: CATEGORY_LABELS
  });
}));

/* ---------------------------- Complaints -------------------------- */
function buildQuery(user, q) {
  const mongo = {};
  if (user.role === 'student') {
    const studentId = toObjectId(user.id);
    if (studentId) mongo.student = studentId;
    else mongo._id = { $in: [] };
  } else if (user.role === 'department') {
    const deptId = toObjectId(user.department);
    if (deptId) mongo.department = deptId;
    else mongo._id = { $in: [] };
  } else if (q.student) {
    const studentId = toObjectId(q.student);
    if (studentId) mongo.student = studentId;
    else mongo._id = { $in: [] };
  }

  if (q.status) mongo.status = { $in: String(q.status).split(',') };
  if (q.priority) mongo.priority = { $in: String(q.priority).split(',') };
  if (q.category) mongo.category = { $in: String(q.category).split(',') };
  if (q.department) {
    const deptId = toObjectId(q.department);
    if (deptId) mongo.department = deptId;
    else mongo._id = { $in: [] };
  }
  if (q.sla === 'breached') mongo.slaBreached = true;
  if (q.escalated === '1') mongo.escalated = true;
  if (q.open === '1') mongo.status = { $nin: ['closed', 'resolved'] };
  if (q.unassigned === '1') mongo.department = null;
  if (q.q) {
    const rx = new RegExp(String(q.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    mongo.$or = [{ title: rx }, { description: rx }, { ticketId: rx }, { location: rx }];
  }
  return mongo;
}

function serializeComplaint(c, { detail = false } = {}) {
  const obj = {
    id: c._id,
    ticketId: c.ticketId,
    title: c.title,
    description: c.description,
    category: c.category,
    categoryLabel: CATEGORY_LABELS[c.category] || 'General',
    priority: c.priority,
    location: c.location,
    status: c.status,
    statusLabel: STATUS_LABEL[c.status],
    student: c.student && c.student._id
      ? { id: c.student._id, name: c.student.name, email: c.student.email, rollNo: c.student.rollNo }
      : c.student,
    department: c.department && c.department._id
      ? { id: c.department._id, name: c.department.name, category: c.department.category }
      : c.department,
    hasImage: !!c.imageFileId,
    imageFilename: c.imageFilename,
    imageSize: c.imageSize,
    slaHours: c.slaHours,
    slaDueAt: c.slaDueAt,
    slaBreached: c.slaBreached,
    escalated: c.escalated,
    escalatedReason: c.escalatedReason,
    resolutionRemarks: c.resolutionRemarks,
    autoCategory: c.autoCategory,
    autoPriority: c.autoPriority,
    autoAssigned: c.autoAssigned,
    resolvedAt: c.resolvedAt,
    closedAt: c.closedAt,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
    commentCount: (c.comments || []).length
  };
  if (detail) {
    obj.description = c.description;
    obj.comments = (c.comments || []).map((m) => ({ id: m._id, byName: m.byName, byRole: m.byRole, text: m.text, at: m.at }));
    obj.timeline = (c.timeline || []).map((t) => ({ id: t._id, action: t.action, note: t.note, byName: t.byName, byRole: t.byRole, at: t.at }));
  }
  return obj;
}

app.get('/api/complaints', auth, wrap(async (req, res) => {
  const mongo = buildQuery(req.user, req.query);
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
  const sort = req.query.sort === 'oldest' ? { createdAt: 1 } : { createdAt: -1 };

  const [items, total] = await Promise.all([
    Complaint.find(mongo).sort(sort).skip((page - 1) * limit).limit(limit)
      .populate('student', 'name email rollNo')
      .populate('department', 'name category'),
    Complaint.countDocuments(mongo)
  ]);
  res.json({
    complaints: items.map((c) => serializeComplaint(c)),
    total, page, pages: Math.ceil(total / limit) || 1
  });
}));

app.get('/api/complaints/:id', auth, wrap(async (req, res) => {
  const c = await Complaint.findById(req.params.id)
    .populate('student', 'name email rollNo phone')
    .populate('department', 'name category email');
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  if (!canAccess(req.user, c)) return res.status(403).json({ error: 'You do not have access to this complaint' });
  res.json({ complaint: serializeComplaint(c, { detail: true }) });
}));

app.post('/api/complaints', auth, requireRole('student'), upload.single('image'), wrap(async (req, res) => {
  const { title, description, category = '', priority = '', location = '' } = req.body || {};
  if (!title || !description) return res.status(400).json({ error: 'Title and description are required' });

  const detected = detectCategory(`${title} ${description}`);
  const finalCategory = category && category !== 'auto' ? String(category).toLowerCase() : detected.category;
  const rec = recommendPriority(`${title} ${description}`);
  const finalPriority = priority && priority !== 'auto' ? String(priority).toLowerCase() : rec.priority;
  const slaHours = SLA_HOURS[finalPriority] || 24;

  let dept = await Department.findOne({ category: finalCategory, active: true });
  if (!dept) dept = await Department.findOne({ category: 'general', active: true });

  const complaint = new Complaint({
    ticketId: await makeTicketId(),
    title, description, location,
    category: finalCategory,
    priority: finalPriority,
    slaHours,
    slaDueAt: new Date(Date.now() + slaHours * 3600 * 1000),
    student: req.user.id,
    department: dept ? dept._id : null,
    status: dept ? 'assigned' : 'submitted',
    autoCategory: !category || category === 'auto',
    autoPriority: !priority || priority === 'auto',
    autoAssigned: true
  });

  if (req.file) {
    const filename = `${Date.now()}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    const stream = bucket.openUploadStream(filename, { contentType: req.file.mimetype });
    const fileId = await new Promise((resolve, reject) => {
      stream.on('finish', () => resolve(stream.id));
      stream.on('error', reject);
      stream.end(req.file.buffer);
    });
    complaint.imageFileId = fileId;
    complaint.imageFilename = req.file.originalname;
    complaint.imageMimeType = req.file.mimetype;
    complaint.imageSize = req.file.size;
  }

  pushTimeline(complaint, 'Complaint Submitted', req.user,
    `Category: ${CATEGORY_LABELS[finalCategory] || finalCategory} | Priority: ${finalPriority} | SLA: ${slaHours}h`);
  if (dept) pushTimeline(complaint, 'Auto Assigned', { name: 'System', role: 'system' }, `Assigned to ${dept.name}`);

  await complaint.save();
  await complaint.populate([
    { path: 'student', select: 'name email rollNo' },
    { path: 'department', select: 'name category' }
  ]);
  await logActivity({ action: 'complaint_created', detail: `Complaint ${complaint.ticketId} "${complaint.title}" created`, user: req.user, ticketId: complaint.ticketId });

  const payload = {
    title: 'New complaint received',
    message: `${complaint.ticketId} - ${complaint.title}`,
    type: 'complaint',
    ticketId: complaint.ticketId
  };
  if (dept) await notifyRole('department', payload, dept._id);
  await notifyRole('admin', payload);

  res.status(201).json({ complaint: serializeComplaint(complaint), message: 'Complaint submitted successfully' });
}));

app.post('/api/complaints/:id/comments', auth, wrap(async (req, res) => {
  const { text } = req.body || {};
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  const c = await Complaint.findById(req.params.id).populate('student', 'name').populate('department', 'name');
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  if (!canAccess(req.user, c)) return res.status(403).json({ error: 'You do not have access to this complaint' });

  c.comments.push({ byName: req.user.name, byRole: req.user.role, text: String(text).trim() });
  pushTimeline(c, 'Comment Added', req.user, String(text).trim().slice(0, 120));
  await c.save();

  if (req.user.role === 'student') {
    if (c.department) await notifyRole('department', { title: 'New comment on ' + c.ticketId, message: String(text).slice(0, 140), type: 'comment', ticketId: c.ticketId }, c.department._id);
    await notifyRole('admin', { title: 'New comment on ' + c.ticketId, message: String(text).slice(0, 140), type: 'comment', ticketId: c.ticketId });
  } else if (req.user.role !== 'student') {
    await notify(c.student._id, { title: 'Reply on ' + c.ticketId, message: String(text).slice(0, 140), type: 'comment', ticketId: c.ticketId, complaint: c._id });
  }
  res.json({ ok: true, message: 'Comment added' });
}));

app.patch('/api/complaints/:id/status', auth, requireRole('department', 'admin'), wrap(async (req, res) => {
  const { status, resolutionRemarks = '', note = '' } = req.body || {};
  const c = await Complaint.findById(req.params.id).populate('student', 'name').populate('department', 'name');
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  if (req.user.role === 'department' && !sameDept(c.department, req.user.department)) {
    return res.status(403).json({ error: 'This complaint is not assigned to your department' });
  }
  const allowed = ALLOWED_TRANSITIONS[c.status] || [];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: `Cannot move from "${STATUS_LABEL[c.status]}" to "${STATUS_LABEL[status] || status}"` });
  }
  if (status === 'resolved' && req.user.role === 'department' && !String(resolutionRemarks).trim()) {
    return res.status(400).json({ error: 'Resolution remarks are required to resolve a complaint' });
  }

  c.status = status;
  if (status === 'resolved') { c.resolvedAt = new Date(); c.resolutionRemarks = resolutionRemarks; c.escalated = false; }
  if (status === 'closed') c.closedAt = new Date();
  if (status === 'in_progress' && c.escalated && c.escalatedReason && !c.slaBreached) { c.escalated = false; }

  pushTimeline(c, `Status changed to ${STATUS_LABEL[status]}`, req.user, resolutionRemarks || note);
  await c.save();

  await logActivity({ action: 'status_change', detail: `${c.ticketId} moved to ${STATUS_LABEL[status]}`, user: req.user, ticketId: c.ticketId });
  await notify(c.student._id, {
    title: `Complaint ${STATUS_LABEL[status]}`,
    message: `${c.ticketId} is now ${STATUS_LABEL[status]}`,
    type: 'status', ticketId: c.ticketId, complaint: c._id
  });
  if (status === 'resolved') {
    await notifyRole('admin', { title: `Resolved: ${c.ticketId}`, message: c.title, type: 'status', ticketId: c.ticketId }, null);
  }
  res.json({ ok: true, message: `Complaint marked as ${STATUS_LABEL[status]}` });
}));

app.post('/api/complaints/:id/escalate', auth, requireRole('department', 'admin'), wrap(async (req, res) => {
  const { reason = '' } = req.body || {};
  const c = await Complaint.findById(req.params.id).populate('student', 'name').populate('department', 'name');
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  if (req.user.role === 'department' && !sameDept(c.department, req.user.department)) {
    return res.status(403).json({ error: 'This complaint is not assigned to your department' });
  }
  if (['resolved', 'closed'].includes(c.status)) return res.status(400).json({ error: 'Resolved/closed complaints cannot be escalated' });

  c.status = 'escalated';
  c.escalated = true;
  c.escalatedReason = reason || 'Escalated by ' + req.user.name;
  pushTimeline(c, 'Escalated', req.user, c.escalatedReason);
  await c.save();

  await logActivity({ action: 'escalate', detail: `${c.ticketId} escalated: ${c.escalatedReason}`, user: req.user, ticketId: c.ticketId });
  await notifyRole('admin', { title: 'Escalated: ' + c.ticketId, message: c.title, type: 'escalated', ticketId: c.ticketId, complaint: c._id });
  await notify(c.student._id, { title: 'Complaint escalated', message: `${c.ticketId} has been escalated`, type: 'escalated', ticketId: c.ticketId, complaint: c._id });
  res.json({ ok: true, message: 'Complaint escalated' });
}));

app.post('/api/complaints/:id/assign', auth, requireRole('admin'), wrap(async (req, res) => {
  const { departmentId } = req.body || {};
  if (departmentId !== undefined && departmentId !== '' && !toObjectId(departmentId)) {
    return res.status(400).json({ error: 'Invalid identifier' });
  }
  const c = await Complaint.findById(req.params.id).populate('student', 'name').populate('department', 'name');
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  const dept = departmentId ? await Department.findById(departmentId) : null;
  if (departmentId && !dept) return res.status(400).json({ error: 'Department not found' });
  if (dept && !dept.active) return res.status(400).json({ error: 'Department is inactive' });

  const prev = c.department;
  c.department = dept ? dept._id : null;
  if (dept && ['submitted'].includes(c.status)) c.status = 'assigned';
  pushTimeline(c, dept ? 'Assigned to Department' : 'Unassigned', req.user,
    dept ? `${dept.name}${prev ? ' (replacing previous assignment)' : ''}` : 'Removed from department queue');
  await c.save();

  await logActivity({
    action: 'assign',
    detail: `${c.ticketId} ${dept ? 'assigned to ' + dept.name : 'unassigned'}`,
    user: req.user, ticketId: c.ticketId
  });
  if (dept) {
    await notifyRole('department', { title: 'New complaint assigned', message: `${c.ticketId} - ${c.title}`, type: 'assign', ticketId: c.ticketId, complaint: c._id }, dept._id);
  }
  await notify(c.student._id, { title: 'Complaint assigned', message: `${c.ticketId} assigned to ${dept ? dept.name : 'no department'}`, type: 'status', ticketId: c.ticketId, complaint: c._id });
  res.json({ ok: true, message: dept ? `Assigned to ${dept.name}` : 'Complaint unassigned' });
}));

app.post('/api/complaints/:id/close', auth, wrap(async (req, res) => {
  const c = await Complaint.findById(req.params.id).populate('student', 'name').populate('department', 'name');
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  const isOwner = req.user.role === 'student' && String(c.student?._id) === req.user.id;
  if (!isOwner && req.user.role !== 'admin') return res.status(403).json({ error: 'Not allowed' });
  if (c.status !== 'resolved') return res.status(400).json({ error: 'Only resolved complaints can be closed' });

  c.status = 'closed';
  c.closedAt = new Date();
  pushTimeline(c, 'Closed', req.user, 'Confirmed by student');
  await c.save();
  await logActivity({ action: 'close', detail: `${c.ticketId} closed`, user: req.user, ticketId: c.ticketId });
  if (c.department) await notifyRole('department', { title: 'Closed: ' + c.ticketId, message: c.title, type: 'status', ticketId: c.ticketId }, c.department._id);
  res.json({ ok: true, message: 'Complaint closed. Thank you for confirming.' });
}));

app.get('/api/complaints/:id/image', auth, wrap(async (req, res) => {
  const c = await Complaint.findById(req.params.id);
  if (!c) return res.status(404).json({ error: 'Complaint not found' });
  if (!canAccess(req.user, c)) return res.status(403).json({ error: 'No access' });
  if (!c.imageFileId) return res.status(404).json({ error: 'No image attached' });

  res.set('Content-Type', c.imageMimeType || 'application/octet-stream');
  const stream = bucket.openDownloadStream(c.imageFileId);
  stream.on('error', () => { if (!res.headersSent) res.status(404).json({ error: 'Image not found in storage' }); });
  stream.pipe(res);
}));

/* --------------------------- Notifications ------------------------ */
app.get('/api/notifications', auth, wrap(async (req, res) => {
  const [items, unread] = await Promise.all([
    Notification.find({ user: req.user.id }).sort({ createdAt: -1 }).limit(50),
    Notification.countDocuments({ user: req.user.id, read: false })
  ]);
  res.json({
    notifications: items.map((n) => ({
      id: n._id, title: n.title, message: n.message, type: n.type,
      ticketId: n.ticketId, read: n.read, createdAt: n.createdAt,
      complaintId: n.complaint
    })),
    unread
  });
}));

app.post('/api/notifications/read-all', auth, wrap(async (req, res) => {
  await Notification.updateMany({ user: req.user.id, read: false }, { read: true });
  res.json({ ok: true });
}));

app.patch('/api/notifications/:id/read', auth, wrap(async (req, res) => {
  await Notification.updateOne({ _id: req.params.id, user: req.user.id }, { read: true });
  res.json({ ok: true });
}));

/* ------------------------------ Stats ----------------------------- */
async function countFor(match) { return Complaint.countDocuments(match); }

app.get('/api/stats', auth, wrap(async (req, res) => {
  const base = {};
  if (req.user.role === 'student') {
    const studentId = toObjectId(req.user.id);
    if (studentId) base.student = studentId;
    else base._id = { $in: [] };
  }
  if (req.user.role === 'department') {
    const deptId = toObjectId(req.user.department);
    if (deptId) base.department = deptId;
    else base._id = { $in: [] };
  }

  const openStatuses = { $nin: ['closed', 'resolved'] };
  const [total, pending, inProgress, resolved, closed, escalated, breached, unassigned, students, departments] = await Promise.all([
    countFor(base),
    countFor({ ...base, status: 'submitted' }),
    countFor({ ...base, status: 'in_progress' }),
    countFor({ ...base, status: { $in: ['resolved', 'closed'] } }),
    countFor({ ...base, status: 'closed' }),
    countFor({ ...base, escalated: true, status: { $ne: 'closed' } }),
    countFor({ ...base, slaBreached: true, status: openStatuses }),
    req.user.role === 'admin' ? countFor({ department: null, status: { $ne: 'closed' } }) : 0,
    req.user.role === 'admin' ? User.countDocuments({ role: 'student' }) : 0,
    req.user.role === 'admin' ? Department.countDocuments() : 0
  ]);

  const assigned = req.user.role === 'department' ? await countFor({ ...base, status: { $nin: ['closed'] } }) : 0;

  const catAgg = await Complaint.aggregate([
    { $match: base },
    { $group: { _id: '$category', count: { $sum: 1 } } },
    { $sort: { count: -1 } }
  ]);
  const priAgg = await Complaint.aggregate([
    { $match: base },
    { $group: { _id: '$priority', count: { $sum: 1 } } }
  ]);

  res.json({
    stats: {
      total, pending, inProgress, resolved, closed, escalated, breached, unassigned,
      assigned, students, departments,
      open: await countFor({ ...base, status: openStatuses }),
      byCategory: catAgg.map((x) => ({ key: x._id || 'general', label: CATEGORY_LABELS[x._id] || 'General', count: x.count })),
      byPriority: ['high', 'medium', 'low'].map((p) => ({ key: p, count: (priAgg.find((x) => x._id === p) || {}).count || 0 }))
    }
  });
}));

app.get('/api/admin/analytics', auth, requireRole('admin'), wrap(async (req, res) => {
  const now = new Date();
  const days = 14;
  const since = new Date(now.getTime() - (days - 1) * 24 * 3600 * 1000);
  since.setHours(0, 0, 0, 0);

  const [statusAgg, catAgg, trendAgg, slaAvg, byDept] = await Promise.all([
    Complaint.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
    Complaint.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
    Complaint.aggregate([
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]),
    Complaint.aggregate([
      { $match: { resolvedAt: { $ne: null } } },
      { $project: { hours: { $divide: [{ $subtract: ['$resolvedAt', '$createdAt'] }, 3600000] } } },
      { $group: { _id: null, avg: { $avg: '$hours' }, max: { $max: '$hours' }, min: { $min: '$hours' } } }
    ]),
    Department.aggregate([
      { $lookup: { from: 'complaints', localField: '_id', foreignField: 'department', as: 'c' } },
      { $project: { name: 1, category: 1, total: { $size: '$c' },
        resolved: { $size: { $filter: { input: '$c', as: 'x', cond: { $in: ['$$x.status', ['resolved', 'closed']] } } } },
        breached: { $size: { $filter: { input: '$c', as: 'x', cond: { $eq: ['$$x.slaBreached', true] } } } } } },
      { $sort: { total: -1 } }
    ])
  ]);

  const trend = [];
  for (let i = 0; i < days; i++) {
    const d = new Date(since.getTime() + i * 24 * 3600 * 1000);
    const key = d.toISOString().slice(0, 10);
    const found = trendAgg.find((x) => x._id === key);
    trend.push({ date: key, count: found ? found.count : 0 });
  }

  const total = await Complaint.countDocuments();
  const resolvedTotal = await Complaint.countDocuments({ status: { $in: ['resolved', 'closed'] } });

  res.json({
    byStatus: Object.entries(statusAgg).length
      ? statusAgg.map((x) => ({ key: x._id, label: STATUS_LABEL[x._id], count: x.count }))
      : [],
    byCategory: catAgg.map((x) => ({ key: x._id, label: CATEGORY_LABELS[x._id] || 'General', count: x.count })),
    trend,
    resolution: {
      avgHours: slaAvg[0] ? Math.round(slaAvg[0].avg * 10) / 10 : 0,
      fastest: slaAvg[0] ? Math.round(slaAvg[0].min * 10) / 10 : 0,
      slowest: slaAvg[0] ? Math.round(slaAvg[0].max * 10) / 10 : 0,
      rate: total ? Math.round((resolvedTotal / total) * 100) : 0
    },
    byDepartment: byDept.map((d) => ({ id: d._id, name: d.name, total: d.total, resolved: d.resolved, breached: d.breached }))
  });
}));

app.get('/api/admin/activity', auth, requireRole('admin'), wrap(async (req, res) => {
  const limit = Math.min(200, parseInt(req.query.limit || '60', 10));
  const items = await ActivityLog.find().sort({ createdAt: -1 }).limit(limit);
  res.json({
    logs: items.map((l) => ({
      id: l._id, action: l.action, detail: l.detail,
      actorName: l.actorName, actorRole: l.actorRole, ticketId: l.ticketId, createdAt: l.createdAt
    }))
  });
}));

/* --------------------- Admin: users & departments ----------------- */
app.get('/api/admin/users', auth, requireRole('admin'), wrap(async (req, res) => {
  const q = {};
  if (req.query.role) q.role = req.query.role;
  if (req.query.q) {
    const rx = new RegExp(String(req.query.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    q.$or = [{ name: rx }, { email: rx }, { rollNo: rx }];
  }
  const users = await User.find(q).populate('department', 'name').sort({ createdAt: -1 }).limit(300);
  const counts = await User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]);
  res.json({
    users: users.map((u) => ({
      id: u._id, name: u.name, email: u.email, role: u.role, rollNo: u.rollNo,
      phone: u.phone, active: u.active, createdAt: u.createdAt,
      department: u.department ? { id: u.department._id, name: u.department.name } : null
    })),
    counts: counts.reduce((a, x) => ({ ...a, [x._id]: x.count }), {})
  });
}));

app.post('/api/admin/users', auth, requireRole('admin'), wrap(async (req, res) => {
  const { name, email, password, role = 'student', departmentId = '', rollNo = '', phone = '' } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (role === 'department' && !departmentId) return res.status(400).json({ error: 'Choose a department for a department account' });
  if (departmentId && !toObjectId(departmentId)) return res.status(400).json({ error: 'Invalid identifier' });
  const exists = await User.exists({ email: String(email).toLowerCase() });
  if (exists) return res.status(400).json({ error: 'Email already in use' });

  const user = await User.create({
    name, email, password: await bcrypt.hash(password, 10), role,
    department: role === 'department' ? departmentId : null, rollNo, phone
  });
  await logActivity({ action: 'user_create', detail: `Created ${role} account "${name}"`, user: req.user });
  res.json({ ok: true, message: 'User created', id: user._id });
}));

app.patch('/api/admin/users/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const { active, name, role, departmentId, password } = req.body || {};
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid identifier' });
  if (departmentId !== undefined && departmentId !== '' && !toObjectId(departmentId)) {
    return res.status(400).json({ error: 'Invalid identifier' });
  }
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (String(user._id) === req.user.id && active === false) return res.status(400).json({ error: 'You cannot deactivate your own account' });

  if (active !== undefined) user.active = !!active;
  if (name) user.name = name;
  if (role) user.role = role;
  if (role === 'department' || user.role === 'department') user.department = departmentId || user.department;
  if (password) {
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    user.password = await bcrypt.hash(password, 10);
  }
  await user.save();
  await logActivity({ action: 'user_update', detail: `Updated user "${user.name}"`, user: req.user });
  res.json({ ok: true, message: 'User updated' });
}));

app.delete('/api/admin/users/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account' });
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid identifier' });
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const owned = await Complaint.countDocuments({ student: user._id, status: { $nin: ['closed', 'resolved'] } });
  if (owned) return res.status(400).json({ error: 'User has open complaints. Deactivate instead.' });
  await user.deleteOne();
  await logActivity({ action: 'user_delete', detail: `Deleted user "${user.name}"`, user: req.user });
  res.json({ ok: true, message: 'User deleted' });
}));

app.post('/api/admin/departments', auth, requireRole('admin'), wrap(async (req, res) => {
  const { name, category = '', description = '', email = '' } = req.body || {};
  if (!name || !category) return res.status(400).json({ error: 'Name and category are required' });
  const exists = await Department.exists({ category: String(category).toLowerCase() });
  if (exists) return res.status(400).json({ error: 'A department for this category already exists' });
  const d = await Department.create({ name, category: String(category).toLowerCase(), description, email });
  await logActivity({ action: 'department_create', detail: `Created department "${name}"`, user: req.user });
  res.json({ ok: true, message: 'Department created', id: d._id });
}));

app.patch('/api/admin/departments/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const { name, description, email, active } = req.body || {};
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid identifier' });
  const d = await Department.findById(req.params.id);
  if (!d) return res.status(404).json({ error: 'Department not found' });
  if (name) d.name = name;
  if (description !== undefined) d.description = description;
  if (email !== undefined) d.email = email;
  if (active !== undefined) d.active = !!active;
  await d.save();
  await logActivity({ action: 'department_update', detail: `Updated department "${d.name}"`, user: req.user });
  res.json({ ok: true, message: 'Department updated' });
}));

/* ------------------------------ Errors ---------------------------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found' }));
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Image must be smaller than 5 MB' : err.message });
  }
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: Object.values(err.errors).map((e) => e.message).join(', ') });
  }
  if (err.name === 'CastError' || err.name === 'BSONError' || err.name === 'BSONTypeError') {
    return res.status(400).json({ error: 'Invalid identifier' });
  }
  console.error(err);
  res.status(500).json({ error: err.message || 'Server error' });
});

app.get('/dashboard', (req, res) => res.sendFile(path.join(publicDir, 'dashboard.html')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(publicDir, 'index.html'));
});

/* --------------------------- Seed & start ------------------------- */
async function seed() {
  const defaults = [
    { name: 'Electrical Department', category: 'electrical', description: 'Fans, lights, power supply, wiring and electrical fittings', email: 'electrical@campus.edu' },
    { name: 'IT & Network Department', category: 'it', description: 'Wi-Fi, internet, computer labs, software and network issues', email: 'it@campus.edu' },
    { name: 'Plumbing Department', category: 'plumbing', description: 'Water supply, pipes, taps, washrooms and drainage', email: 'plumbing@campus.edu' },
    { name: 'Housekeeping Department', category: 'housekeeping', description: 'Cleaning, garbage disposal, pest control and sanitation', email: 'housekeeping@campus.edu' },
    { name: 'Furniture & Carpentry', category: 'furniture', description: 'Chairs, tables, benches, doors, windows and woodwork', email: 'furniture@campus.edu' },
    { name: 'General Maintenance', category: 'general', description: 'Civil work, painting, grounds and everything else', email: 'maintenance@campus.edu' }
  ];
  for (const d of defaults) {
    const exists = await Department.findOne({ category: d.category });
    if (!exists) await Department.create(d);
  }

  const adminEmail = ADMIN_EMAIL.toLowerCase();
  const admin = await User.findOne({ email: adminEmail });
  if (!admin) {
    await User.create({
      name: ADMIN_NAME, email: adminEmail, password: await bcrypt.hash(ADMIN_PASSWORD, 10), role: 'admin'
    });
    console.log(`[seed] Super admin created: ${adminEmail}`);
  }

  if (ENABLE_DEMO_ACCOUNTS === 'true') {
    const samples = [
      { name: 'Priya Menon', email: 'student@campus.edu', role: 'student', rollNo: 'CS-2024-017', department: null },
      { name: 'R. Krishnan (Electrical)', email: 'electrical@campus.edu', role: 'department',
        department: await Department.findOne({ category: 'electrical' }).then((d) => (d ? d._id : null)) }
    ];
    for (const s of samples) {
      const exists = await User.findOne({ email: s.email });
      if (exists && s.role === 'department' && s.department) {
        const linked = exists.department ? await Department.exists({ _id: exists.department }) : null;
        if (!linked || String(exists.department) !== String(s.department)) {
          exists.department = s.department;
          await exists.save();
          console.log(`[seed] Re-linked ${s.email} to its department`);
        }
      }
      if (!exists) {
        await User.create({ ...s, password: await bcrypt.hash('Demo@123', 10), active: true });
        console.log(`[seed] Demo account created: ${s.email} (password: Demo@123)`);
      }
    }
  }
}

/* SLA monitor: runs every minute */
function startSlaMonitor() {
  const tick = async () => {
    try {
      const overdue = await Complaint.find({
        slaDueAt: { $lte: new Date() },
        slaBreached: false,
        status: { $nin: ['resolved', 'closed'] }
      }).populate('department', 'name').populate('student', 'name');

      for (const c of overdue) {
        c.slaBreached = true;
        c.slaBreachedAt = new Date();
        if (c.status !== 'escalated') c.status = 'escalated';
        c.escalated = true;
        c.escalatedReason = c.escalatedReason || `SLA breached - not resolved within ${c.slaHours}h`;
        pushTimeline(c, 'SLA Breached - Escalated', { name: 'SLA Monitor', role: 'system' },
          `Resolution time exceeded (${c.slaHours}h)`);
        await c.save();
        await logActivity({ action: 'sla_breach', detail: `${c.ticketId} breached its ${c.slaHours}h SLA`, ticketId: c.ticketId });
        await notifyRole('admin', { title: 'SLA Breached: ' + c.ticketId, message: c.title, type: 'sla', ticketId: c.ticketId, complaint: c._id });
        if (c.department) await notifyRole('department', { title: 'SLA Breached: ' + c.ticketId, message: c.title, type: 'sla', ticketId: c.ticketId }, c.department._id);
        await notify(c.student?._id, { title: 'SLA breached on ' + c.ticketId, message: 'Your complaint was escalated automatically', type: 'sla', ticketId: c.ticketId, complaint: c._id });
      }
      if (overdue.length) console.log(`[sla] ${overdue.length} complaint(s) breached`);
    } catch (e) {
      console.error('[sla] monitor error', e.message);
    }
  };
  setInterval(tick, 60 * 1000);
  setTimeout(tick, 3000);
}

async function start() {
  await mongoose.connect(MONGODB_URI);
  console.log('[db] connected to MongoDB');
  bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'complaint_images' });
  await seed();
  startSlaMonitor();
  app.listen(PORT, () => {
    console.log(`[app] Smart Cloud Complaint Management running at http://localhost:${PORT}`);
    console.log(`[app] Login page: http://localhost:${PORT}/`);
  });
}

start().catch((e) => {
  console.error('[fatal] failed to start:', e.message);
  process.exit(1);
});
