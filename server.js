const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
const CLASSES_FILE = path.join(DATA, 'classes.json');
const REPORTS_FILE = path.join(DATA, 'reports.json');
const USERS_FILE = path.join(DATA, 'users.json');
const SESSIONS_FILE = path.join(DATA, 'sessions.json');
const sessions = new Map();
const SESSION_COOKIE_MAX_AGE = 10 * 365 * 24 * 60 * 60;
const PASSWORD_BYTES = 64;

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });

if (!fs.existsSync(CLASSES_FILE)) {
  const def = [10, 11, 12].map((k) => ({
    khoi: 'Khối ' + k,
    lop: [1, 2, 3, 4, 5, 6].map((n) => ({ ten: `${k}A${n}`, siSo: 40 })),
  }));
  fs.writeFileSync(CLASSES_FILE, JSON.stringify(def, null, 2));
}
if (!fs.existsSync(REPORTS_FILE)) fs.writeFileSync(REPORTS_FILE, '[]');

const readJSON = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const writeJSON = (f, value) => fs.writeFileSync(f, JSON.stringify(value, null, 2));
const send = (res, code, obj, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(obj));
};
const MIME = { '.html': 'text/html; charset=utf-8', '.jpg': 'image/jpeg', '.js': 'text/javascript', '.css': 'text/css' };

function serveFile(res, file) {
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
}

function saveUsers(users) {
  writeJSON(USERS_FILE, users);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, PASSWORD_BYTES).toString('hex');
  return { salt, hash };
}

function initializeUsers() {
  if (fs.existsSync(USERS_FILE)) {
    const users = readJSON(USERS_FILE);
    if (!Array.isArray(users)) throw new Error('data/users.json phải là một danh sách tài khoản hợp lệ.');
    return;
  }
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password) {
    throw new Error('Chưa có tài khoản. Hãy đặt ADMIN_USERNAME và ADMIN_PASSWORD để tạo admin đầu tiên.');
  }
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    throw new Error('ADMIN_USERNAME phải dài 3-32 ký tự và chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang.');
  }
  if (password.length < 12) throw new Error('ADMIN_PASSWORD phải có ít nhất 12 ký tự.');
  saveUsers([{ id: crypto.randomUUID(), username, role: 'admin', ...hashPassword(password) }]);
}

function userFromRequest(req) {
  const match = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([a-f0-9]+)/);
  if (!match) return null;
  const key = sessionKey(match[1]);
  const session = sessions.get(key);
  return session ? session.user : null;
}

function requireUser(req, res, adminOnly = false) {
  const user = userFromRequest(req);
  if (!user) {
    send(res, 401, { error: 'Vui lòng đăng nhập' });
    return null;
  }
  if (adminOnly && user.role !== 'admin') {
    send(res, 403, { error: 'Chỉ admin mới được thực hiện thao tác này' });
    return null;
  }
  return user;
}

function readBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > maxBytes) {
        reject(new Error('Dữ liệu gửi lên quá lớn'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch (error) { reject(error); }
    });
    req.on('error', reject);
  });
}

function safeUser(user) {
  return { id: user.id, username: user.username, role: user.role };
}

function sessionKey(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function persistSessions() {
  writeJSON(SESSIONS_FILE, Array.from(sessions, ([key, session]) => ({
    key,
    user: session.user,
  })));
}

function initializeSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) {
    persistSessions();
    return;
  }
  const savedSessions = readJSON(SESSIONS_FILE);
  if (!Array.isArray(savedSessions)) {
    throw new Error('data/sessions.json phải là danh sách phiên đăng nhập hợp lệ.');
  }
  const usersById = new Map(readJSON(USERS_FILE).map((user) => [user.id, user]));
  let removedInvalid = false;
  for (const saved of savedSessions) {
    if (!saved || typeof saved.key !== 'string' || !/^[a-f0-9]{64}$/.test(saved.key)) {
      throw new Error('data/sessions.json chứa phiên đăng nhập không hợp lệ.');
    }
    const user = usersById.get(saved.user && saved.user.id);
    if (!user) {
      removedInvalid = true;
      continue;
    }
    sessions.set(saved.key, { user: safeUser(user) });
  }
  if (removedInvalid || savedSessions.some((saved) => Object.prototype.hasOwnProperty.call(saved, 'expiresAt'))) persistSessions();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'POST' && url.pathname === '/api/login') {
    try {
      const { username, password } = await readBody(req);
      const user = readJSON(USERS_FILE).find((candidate) => candidate.username === username);
      if (!user || typeof password !== 'string') return send(res, 401, { error: 'Tên đăng nhập hoặc mật khẩu không đúng' });
      const attempted = crypto.scryptSync(password, user.salt, PASSWORD_BYTES);
      const stored = Buffer.from(user.hash, 'hex');
      if (attempted.length !== stored.length || !crypto.timingSafeEqual(attempted, stored)) {
        return send(res, 401, { error: 'Tên đăng nhập hoặc mật khẩu không đúng' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      const safe = safeUser(user);
      sessions.set(sessionKey(token), { user: safe });
      persistSessions();
      const secureCookie = process.env.NODE_ENV === 'production' ? '; Secure' : '';
      return send(res, 200, { user: safe }, {
        'Set-Cookie': `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_COOKIE_MAX_AGE}${secureCookie}`,
      });
    } catch (error) {
      return send(res, 400, { error: error.message });
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/logout') {
    const match = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([a-f0-9]+)/);
    if (match && sessions.delete(sessionKey(match[1]))) persistSessions();
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  if (req.method === 'GET' && url.pathname === '/api/session') {
    const user = userFromRequest(req);
    return send(res, 200, { user });
  }

  if (req.method === 'GET' && url.pathname === '/api/classes') {
    if (!requireUser(req, res)) return;
    return send(res, 200, readJSON(CLASSES_FILE));
  }

  if (req.method === 'POST' && url.pathname === '/api/classes') {
    if (!requireUser(req, res, true)) return;
    try {
      const { khoi, lop, siSo } = await readBody(req);
      const grade = typeof khoi === 'string' ? khoi.trim() : '';
      const name = typeof lop === 'string' ? lop.trim() : '';
      const count = Number(siSo);
      if (!grade || grade.length > 32 || /[\u0000-\u001f]/.test(grade)) {
        return send(res, 400, { error: 'Tên khối không hợp lệ' });
      }
      if (!name || name.length > 32 || /[\u0000-\u001f]/.test(name)) {
        return send(res, 400, { error: 'Tên lớp không hợp lệ' });
      }
      if (!Number.isInteger(count) || count <= 0) return send(res, 400, { error: 'Sĩ số không hợp lệ' });
      const data = readJSON(CLASSES_FILE);
      if (data.flatMap((group) => group.lop).some((cls) => cls.ten.toLowerCase() === name.toLowerCase())) {
        return send(res, 409, { error: 'Tên lớp đã tồn tại' });
      }
      let group = data.find((item) => item.khoi.toLowerCase() === grade.toLowerCase());
      if (!group) {
        group = { khoi: grade, lop: [] };
        data.push(group);
      }
      group.lop.push({ ten: name, siSo: count });
      writeJSON(CLASSES_FILE, data);
      return send(res, 201, { ok: true });
    } catch (error) {
      return send(res, 400, { error: error.message });
    }
  }

  const classMatch = url.pathname.match(/^\/api\/classes\/([^/]+)$/);
  if (req.method === 'DELETE' && classMatch) {
    if (!requireUser(req, res, true)) return;
    let name;
    try { name = decodeURIComponent(classMatch[1]); } catch {
      return send(res, 400, { error: 'Tên lớp không hợp lệ' });
    }
    const data = readJSON(CLASSES_FILE);
    const classes = data.flatMap((group) => group.lop);
    if (!classes.some((cls) => cls.ten === name)) return send(res, 404, { error: 'Không tìm thấy lớp' });
    if (classes.length <= 1) return send(res, 400, { error: 'Phải giữ lại ít nhất một lớp' });
    if (readJSON(REPORTS_FILE).some((report) => report.lop === name)) {
      return send(res, 409, { error: 'Lớp còn báo cáo lịch sử; hãy xóa các báo cáo trước' });
    }
    const remainingGroups = data.map((group) => ({
      ...group,
      lop: group.lop.filter((cls) => cls.ten !== name),
    })).filter((group) => group.lop.length > 0);
    writeJSON(CLASSES_FILE, remainingGroups);
    return send(res, 200, { ok: true });
  }

  if (req.method === 'GET' && url.pathname === '/api/reports') {
    if (!requireUser(req, res)) return;
    const date = url.searchParams.get('date');
    const all = readJSON(REPORTS_FILE);
    return send(res, 200, date ? all.filter((r) => r.date === date) : all);
  }

  if (req.method === 'GET' && url.pathname === '/api/users') {
    if (!requireUser(req, res, true)) return;
    return send(res, 200, readJSON(USERS_FILE).map(safeUser));
  }

  if (req.method === 'POST' && url.pathname === '/api/users') {
    if (!requireUser(req, res, true)) return;
    try {
      const { username, password } = await readBody(req);
      if (typeof username !== 'string' || !/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
        return send(res, 400, { error: 'Tên đăng nhập phải dài 3-32 ký tự và chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang' });
      }
      if (typeof password !== 'string' || password.length < 12) {
        return send(res, 400, { error: 'Mật khẩu phải có ít nhất 12 ký tự' });
      }
      const users = readJSON(USERS_FILE);
      if (users.some((user) => user.username.toLowerCase() === username.toLowerCase())) {
        return send(res, 409, { error: 'Tên đăng nhập đã tồn tại' });
      }
      const user = { id: crypto.randomUUID(), username, role: 'teacher', ...hashPassword(password) };
      users.push(user);
      saveUsers(users);
      return send(res, 201, { user: safeUser(user) });
    } catch (error) {
      return send(res, 400, { error: error.message });
    }
  }

  const passwordMatch = url.pathname.match(/^\/api\/users\/([a-f0-9-]+)\/password$/);
  if (req.method === 'POST' && passwordMatch) {
    if (!requireUser(req, res, true)) return;
    try {
      const { password } = await readBody(req);
      if (typeof password !== 'string' || password.length < 12) {
        return send(res, 400, { error: 'Mật khẩu phải có ít nhất 12 ký tự' });
      }
      const users = readJSON(USERS_FILE);
      const target = users.find((candidate) => candidate.id === passwordMatch[1]);
      if (!target) return send(res, 404, { error: 'Không tìm thấy tài khoản' });
      if (target.role !== 'teacher') return send(res, 403, { error: 'Chỉ có thể đặt lại mật khẩu tài khoản giáo viên' });
      Object.assign(target, hashPassword(password));
      saveUsers(users);
      let removedSessions = false;
      for (const [token, session] of sessions) {
        if (session.user.id === target.id) {
          sessions.delete(token);
          removedSessions = true;
        }
      }
      if (removedSessions) persistSessions();
      return send(res, 200, { ok: true });
    } catch (error) {
      return send(res, 400, { error: error.message });
    }
  }

  const userMatch = url.pathname.match(/^\/api\/users\/([a-f0-9-]+)$/);
  if (req.method === 'DELETE' && userMatch) {
    if (!requireUser(req, res, true)) return;
    const users = readJSON(USERS_FILE);
    const target = users.find((candidate) => candidate.id === userMatch[1]);
    if (!target) return send(res, 404, { error: 'Không tìm thấy tài khoản' });
    if (target.role === 'admin') return send(res, 403, { error: 'Không thể xóa tài khoản admin' });
    saveUsers(users.filter((candidate) => candidate.id !== target.id));
    let removedSessions = false;
    for (const [token, session] of sessions) {
      if (session.user.id === target.id) {
        sessions.delete(token);
        removedSessions = true;
      }
    }
    if (removedSessions) persistSessions();
    return send(res, 200, { ok: true });
  }

  if (req.method === 'POST' && url.pathname === '/api/siso') {
    if (!requireUser(req, res)) return;
    try {
      const { lop, siSo } = await readBody(req);
      const n = Number(siSo);
      if (!Number.isInteger(n) || n <= 0) return send(res, 400, { error: 'Sĩ số không hợp lệ' });
      const data = readJSON(CLASSES_FILE);
      const cls = data.flatMap((k) => k.lop).find((l) => l.ten === lop);
      if (!cls) return send(res, 400, { error: 'Lớp không tồn tại' });
      cls.siSo = n;
      writeJSON(CLASSES_FILE, data);
      return send(res, 200, { ok: true });
    } catch (error) {
      return send(res, 400, { error: error.message });
    }
  }

  if (req.method === 'DELETE' && url.pathname === '/api/reports') {
    if (!requireUser(req, res, true)) return;
    const date = url.searchParams.get('date');
    const lop = url.searchParams.get('lop');
    if (!date || !lop) return send(res, 400, { error: 'Thiếu ngày hoặc lớp' });
    const reports = readJSON(REPORTS_FILE);
    const remaining = reports.filter((report) => !(report.date === date && report.lop === lop));
    if (remaining.length === reports.length) return send(res, 404, { error: 'Không tìm thấy báo cáo' });
    writeJSON(REPORTS_FILE, remaining);
    return send(res, 200, { ok: true });
  }

  if (req.method === 'POST' && url.pathname === '/api/submit') {
    const user = requireUser(req, res);
    if (!user) return;
    try {
      const { date, khoi, lop, rows } = await readBody(req, 40 * 1024 * 1024);
      if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Array.isArray(rows)) {
        return send(res, 400, { error: 'Dữ liệu báo cáo không hợp lệ' });
      }
      const classes = readJSON(CLASSES_FILE);
      const cls = classes.flatMap((k) => k.lop).find((l) => l.ten === lop);
      if (!cls) return send(res, 400, { error: 'Lớp không tồn tại' });
      const saved = rows.map((row) => ({
        key: String(row.key || ''),
        label: String(row.label || ''),
        qty: Number(row.qty),
        reason: String(row.reason || ''),
      }));
      if (saved.some((row) => !Number.isInteger(row.qty) || row.qty < 0)) {
        return send(res, 400, { error: 'Số lượng không hợp lệ' });
      }
      const tong = saved.reduce((sum, row) => sum + row.qty, 0);
      if (tong !== cls.siSo) return send(res, 400, { error: `Tổng ${tong} khác sĩ số ${cls.siSo}` });
      const reports = readJSON(REPORTS_FILE);
      const existing = reports.find((report) => report.date === date && report.lop === lop);
      if (existing && existing.createdBy && existing.createdBy !== user.username && user.role !== 'admin') {
        return send(res, 403, { error: 'Báo cáo này do giáo viên khác nộp; chỉ admin mới được thay thế' });
      }
      reports.splice(0, reports.length, ...reports.filter((report) => !(report.date === date && report.lop === lop)));
      reports.push({
        date, khoi, lop, siSo: cls.siSo, tong, rows: saved,
        createdBy: user.username, time: new Date().toISOString(),
      });
      writeJSON(REPORTS_FILE, reports);
      return send(res, 200, { ok: true });
    } catch (error) {
      return send(res, 400, { error: error.message });
    }
  }

  if (url.pathname.startsWith('/uploads/')) {
    return serveFile(res, path.join(UPLOADS, path.basename(url.pathname)));
  }
  if (req.method === 'GET' && url.pathname === '/service-worker.js') {
    return serveFile(res, path.join(__dirname, 'public', 'service-worker.js'));
  }
  serveFile(res, path.join(__dirname, 'public', 'index.html'));
});

try {
  initializeUsers();
  initializeSessions();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

server.listen(PORT, () => console.log(`Chạy tại http://localhost:${server.address().port}`));
