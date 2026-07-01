from flask import Flask, jsonify, request, send_from_directory
import sqlite3, time, os, random, string, datetime, urllib.request, urllib.parse, json, hashlib, threading

app = Flask(__name__, static_folder='static')
# On Railway, mount a volume at /data for persistence; fall back to local dir
_data_dir = os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
os.makedirs(_data_dir, exist_ok=True)
DB = os.path.join(_data_dir, 'data.db')

SESSION_TTL = 12 * 3600
TEMP_TOKENS = {}  # short-lived in-memory temp passwords for forgot-password flow

def hash_pw(pw):
    return hashlib.sha256(('wt_salt_' + pw).encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS locations (
            id TEXT PRIMARY KEY, name TEXT, day_active INTEGER DEFAULT 0)''')
        db.execute('''CREATE TABLE IF NOT EXISTS managers (
            id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT,
            phone TEXT DEFAULT '', is_admin INTEGER DEFAULT 0,
            location_id TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS workers (
            id TEXT PRIMARY KEY, name TEXT, manager TEXT,
            working INTEGER DEFAULT 0, clock_start INTEGER,
            current_location_id TEXT, note TEXT DEFAULT '',
            overtime_active INTEGER DEFAULT 0)''')
        db.execute('''CREATE TABLE IF NOT EXISTS logs (
            id TEXT PRIMARY KEY, worker_id TEXT, worker_name TEXT,
            manager TEXT, clock_in INTEGER, clock_out INTEGER,
            duration_ms INTEGER, overtime INTEGER DEFAULT 0,
            overtime_approved INTEGER DEFAULT 0, overtime_note TEXT,
            location_id TEXT, location_name TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, manager_id TEXT, username TEXT,
            is_admin INTEGER, location_id TEXT, expires REAL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY, worker_id TEXT, worker_name TEXT,
            month INTEGER, year INTEGER, content TEXT, generated_at INTEGER)''')
        db.execute("INSERT OR IGNORE INTO settings VALUES ('day_active','0')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('shift_hours','8')")
        # migrate existing tables
        _migrate(db)
        # default admin
        if not db.execute('SELECT 1 FROM managers').fetchone():
            db.execute('INSERT INTO managers (id,username,password,phone,is_admin,location_id) VALUES (?,?,?,?,1,NULL)',
                       (uid(), 'admin', hash_pw('1234'), ''))

def _migrate(db):
    def cols(table):
        return [r[1] for r in db.execute(f'PRAGMA table_info({table})').fetchall()]
    lc = cols('logs')
    for col, defn in [('overtime','INTEGER DEFAULT 0'),('overtime_approved','INTEGER DEFAULT 0'),
                      ('overtime_note','TEXT'),('location_id','TEXT'),('location_name','TEXT'),
                      ('overtime_requested','INTEGER DEFAULT 0')]:
        if col not in lc:
            db.execute(f'ALTER TABLE logs ADD COLUMN {col} {defn}')
    mc = cols('managers')
    if 'location_id' not in mc:
        db.execute('ALTER TABLE managers ADD COLUMN location_id TEXT')
    wc = cols('workers')
    if 'current_location_id' not in wc:
        db.execute('ALTER TABLE workers ADD COLUMN current_location_id TEXT')
    if 'note' not in wc:
        db.execute('ALTER TABLE workers ADD COLUMN note TEXT DEFAULT ""')
    if 'overtime_active' not in wc:
        db.execute('ALTER TABLE workers ADD COLUMN overtime_active INTEGER DEFAULT 0')
    lcc = cols('locations')
    if 'day_active' not in lcc:
        db.execute('ALTER TABLE locations ADD COLUMN day_active INTEGER DEFAULT 0')

def uid():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

def gen_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def get_setting(key):
    with get_db() as db:
        row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else None

def set_setting(key, value):
    with get_db() as db:
        db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, str(value)))

def _session_row_to_dict(row):
    return {'manager_id': row['manager_id'], 'username': row['username'],
            'is_admin': bool(row['is_admin']), 'location_id': row['location_id'],
            'expires': row['expires']}

def auth(req):
    token = req.headers.get('X-Token') or (req.json or {}).get('_token', '')
    if not token: return None
    with get_db() as db:
        row = db.execute('SELECT * FROM sessions WHERE token=?', (token,)).fetchone()
    if row and time.time() < row['expires']:
        return _session_row_to_dict(row)
    return None

def create_session(token, manager_id, username, is_admin, location_id):
    expires = time.time() + SESSION_TTL
    with get_db() as db:
        db.execute('INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?)',
                   (token, manager_id, username, 1 if is_admin else 0, location_id, expires))
    return {'manager_id': manager_id, 'username': username, 'is_admin': bool(is_admin),
            'location_id': location_id, 'expires': expires}

def delete_session(token):
    with get_db() as db:
        db.execute('DELETE FROM sessions WHERE token=?', (token,))

def purge_expired_sessions():
    with get_db() as db:
        db.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))

def require_auth(req):
    s = auth(req)
    if not s:
        return None, (jsonify({'error': 'unauthorized'}), 401)
    return s, None

@app.after_request
def cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,X-Token'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    r.headers['ngrok-skip-browser-warning'] = 'true'
    return r

# ── Locations ──────────────────────────────────────────────────────────────
@app.route('/api/locations', methods=['GET'])
def get_locations():
    with get_db() as db:
        rows = db.execute('SELECT * FROM locations ORDER BY name').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/locations', methods=['POST', 'OPTIONS'])
def add_location():
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    name = (request.json or {}).get('name', '').strip()
    if not name: return jsonify({'error': 'name required'}), 400
    lid = uid()
    with get_db() as db:
        db.execute('INSERT INTO locations (id, name, day_active) VALUES (?,?,0)', (lid, name))
    return jsonify({'id': lid, 'name': name})

@app.route('/api/locations/<lid>', methods=['DELETE', 'OPTIONS'])
def delete_location(lid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    with get_db() as db:
        # unassign managers from this location
        db.execute('UPDATE managers SET location_id=NULL WHERE location_id=?', (lid,))
        db.execute('DELETE FROM locations WHERE id=?', (lid,))
    return jsonify({'ok': True})

@app.route('/api/locations/swap', methods=['POST', 'OPTIONS'])
def swap_locations():
    """Swap which manager is assigned to each of two locations."""
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    d = request.json or {}
    loc1_id, loc2_id = d.get('loc1'), d.get('loc2')
    if not loc1_id or not loc2_id or loc1_id == loc2_id:
        return jsonify({'error': 'need two different location ids'}), 400
    with get_db() as db:
        m1 = db.execute('SELECT id FROM managers WHERE location_id=?', (loc1_id,)).fetchone()
        m2 = db.execute('SELECT id FROM managers WHERE location_id=?', (loc2_id,)).fetchone()
        if m1: db.execute('UPDATE managers SET location_id=? WHERE id=?', (loc2_id, m1['id']))
        if m2: db.execute('UPDATE managers SET location_id=? WHERE id=?', (loc1_id, m2['id']))
    return jsonify({'ok': True})

@app.route('/api/managers/<mid>/location', methods=['POST', 'OPTIONS'])
def assign_location(mid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    lid = (request.json or {}).get('location_id')  # None to unassign
    with get_db() as db:
        db.execute('UPDATE managers SET location_id=? WHERE id=?', (lid, mid))
    return jsonify({'ok': True})

# ── Manager Auth ───────────────────────────────────────────────────────────
@app.route('/api/managers/login', methods=['POST', 'OPTIONS'])
def manager_login():
    if request.method == 'OPTIONS': return '', 200
    d = request.json or {}
    username = (d.get('username') or '').strip().lower()
    password = d.get('password', '')
    with get_db() as db:
        m = db.execute('SELECT * FROM managers WHERE username=?', (username,)).fetchone()
    if not m or m['password'] != hash_pw(password):
        return jsonify({'ok': False, 'error': 'wrong_credentials'}), 401
    token = gen_token()
    create_session(token, m['id'], m['username'], m['is_admin'], m['location_id'])
    purge_expired_sessions()
    # get location name
    loc_name = None
    if m['location_id']:
        with get_db() as db:
            loc = db.execute('SELECT name FROM locations WHERE id=?', (m['location_id'],)).fetchone()
            if loc: loc_name = loc['name']
    return jsonify({'ok': True, 'token': token, 'id': m['id'], 'username': m['username'],
                    'is_admin': bool(m['is_admin']),
                    'location_id': m['location_id'], 'location_name': loc_name})

@app.route('/api/managers/logout', methods=['POST'])
def manager_logout():
    token = request.headers.get('X-Token', '')
    delete_session(token)
    return jsonify({'ok': True})

@app.route('/api/managers/forgot', methods=['POST', 'OPTIONS'])
def manager_forgot():
    if request.method == 'OPTIONS': return '', 200
    d = request.json or {}
    username = (d.get('username') or '').strip().lower()
    phone    = (d.get('phone') or '').strip()
    with get_db() as db:
        m = db.execute('SELECT * FROM managers WHERE username=?', (username,)).fetchone()
    if not m: return jsonify({'ok': False, 'error': 'not_found'}), 404
    if not m['phone'] or m['phone'] != phone:
        return jsonify({'ok': False, 'error': 'wrong_phone'}), 401
    temp   = ''.join(random.choices(string.digits, k=6))
    TEMP_TOKENS[username] = {'temp_pw': temp, 'expires': time.time() + 900}
    sms_sent = False
    try:
        data = urllib.parse.urlencode({
            'phone': phone,
            'message': f'WorkTrack temp password for {username}: {temp} (valid 15 min)',
            'key': 'textbelt'
        }).encode()
        req = urllib.request.Request('https://textbelt.com/text', data=data, method='POST')
        res = json.loads(urllib.request.urlopen(req, timeout=8).read())
        sms_sent = res.get('success', False)
    except: pass
    return jsonify({'ok': True, 'sent': sms_sent, 'temp_password': temp if not sms_sent else None})

@app.route('/api/managers/login_temp', methods=['POST', 'OPTIONS'])
def manager_login_temp():
    if request.method == 'OPTIONS': return '', 200
    d = request.json or {}
    username = (d.get('username') or '').strip().lower()
    temp_pw  = d.get('temp_pw', '')
    s = TEMP_TOKENS.get(username)
    if not s or temp_pw != s.get('temp_pw') or time.time() > s.get('expires', 0):
        return jsonify({'ok': False, 'error': 'invalid_temp'}), 401
    TEMP_TOKENS.pop(username, None)
    with get_db() as db:
        m = db.execute('SELECT * FROM managers WHERE username=?', (username,)).fetchone()
    if not m: return jsonify({'ok': False}), 404
    token = gen_token()
    create_session(token, m['id'], m['username'], m['is_admin'], m['location_id'])
    return jsonify({'ok': True, 'token': token, 'username': m['username'],
                    'is_admin': bool(m['is_admin']), 'must_change_pw': True})

@app.route('/api/managers', methods=['GET'])
def list_managers():
    s, err = require_auth(request)
    if err: return err
    with get_db() as db:
        rows = db.execute('''SELECT m.id, m.username, m.phone, m.is_admin, m.location_id,
                             l.name as location_name
                             FROM managers m LEFT JOIN locations l ON m.location_id=l.id
                             ORDER BY m.username''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/managers', methods=['POST', 'OPTIONS'])
def add_manager():
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    d = request.json or {}
    username = (d.get('username') or '').strip().lower()
    password = d.get('password', '')
    is_admin = 1 if d.get('is_admin') else 0
    location_id = d.get('location_id') or None
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    try:
        with get_db() as db:
            mid = uid()
            db.execute('INSERT INTO managers VALUES (?,?,?,?,?,?)',
                       (mid, username, hash_pw(password), '', is_admin, location_id))
        return jsonify({'id': mid, 'username': username, 'is_admin': is_admin})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'username_taken'}), 409

@app.route('/api/managers/<mid>', methods=['DELETE', 'OPTIONS'])
def delete_manager(mid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    if mid == s['manager_id']: return jsonify({'error': 'cannot_delete_self'}), 400
    with get_db() as db:
        db.execute('DELETE FROM managers WHERE id=?', (mid,))
    return jsonify({'ok': True})

@app.route('/api/managers/<mid>/password', methods=['POST', 'OPTIONS'])
def change_password(mid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if mid != s['manager_id'] and not s['is_admin']:
        return jsonify({'error': 'forbidden'}), 403
    d = request.json or {}
    new_pw = d.get('new', '')
    if len(new_pw) < 4: return jsonify({'error': 'too_short'}), 400
    if mid == s['manager_id']:
        cur = d.get('current', '')
        with get_db() as db:
            m = db.execute('SELECT password FROM managers WHERE id=?', (mid,)).fetchone()
        if not m or m['password'] != hash_pw(cur):
            return jsonify({'error': 'wrong_current'}), 401
    with get_db() as db:
        db.execute('UPDATE managers SET password=? WHERE id=?', (hash_pw(new_pw), mid))
    return jsonify({'ok': True})

@app.route('/api/managers/<mid>/phone', methods=['POST', 'OPTIONS'])
def save_manager_phone(mid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if mid != s['manager_id'] and not s['is_admin']:
        return jsonify({'error': 'forbidden'}), 403
    phone = (request.json or {}).get('phone', '').strip()
    with get_db() as db:
        db.execute('UPDATE managers SET phone=? WHERE id=?', (phone, mid))
    return jsonify({'ok': True})

@app.route('/api/managers/me', methods=['GET'])
def me():
    s, err = require_auth(request)
    if err: return err
    with get_db() as db:
        m = db.execute('''SELECT m.id, m.username, m.phone, m.is_admin, m.location_id,
                          l.name as location_name
                          FROM managers m LEFT JOIN locations l ON m.location_id=l.id
                          WHERE m.id=?''', (s['manager_id'],)).fetchone()
    return jsonify(dict(m))

# ── Settings ───────────────────────────────────────────────────────────────
@app.route('/api/settings', methods=['GET'])
def get_settings():
    with get_db() as db:
        rows = db.execute('SELECT * FROM settings').fetchall()
    return jsonify({r['key']: r['value'] for r in rows})

@app.route('/api/settings', methods=['POST', 'OPTIONS'])
def update_settings():
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    d = request.json or {}
    for key, value in d.items():
        if not key.startswith('_'):
            set_setting(key, value)
    return jsonify({'ok': True})

# ── Workers ────────────────────────────────────────────────────────────────
@app.route('/api/workers', methods=['GET'])
def get_workers():
    with get_db() as db:
        rows = db.execute('SELECT * FROM workers ORDER BY name').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/workers', methods=['POST', 'OPTIONS'])
def add_worker():
    if request.method == 'OPTIONS': return '', 200
    d = request.json or {}
    name    = (d.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    wid = uid()
    with get_db() as db:
        db.execute('INSERT INTO workers (id,name,manager,working,clock_start,current_location_id,note,overtime_active) VALUES (?,?,?,0,NULL,NULL,?,0)', (wid, name, '', ''))
    return jsonify({'id': wid, 'name': name, 'manager': '', 'working': 0,
                    'clock_start': None, 'current_location_id': None})

@app.route('/api/workers/<wid>', methods=['DELETE', 'OPTIONS'])
def delete_worker(wid):
    if request.method == 'OPTIONS': return '', 200
    with get_db() as db:
        db.execute('DELETE FROM workers WHERE id=?', (wid,))
    return jsonify({'ok': True})

@app.route('/api/workers/<wid>/clock', methods=['POST'])
def clock(wid):
    with get_db() as db:
        w = db.execute('SELECT * FROM workers WHERE id=?', (wid,)).fetchone()
        if not w: return jsonify({'error': 'Not found'}), 404
        now = int(time.time() * 1000)
        shift_ms = float(get_setting('shift_hours') or 8) * 3600000
        if not w['working']:
            location_id = (request.json or {}).get('location_id')
            if not location_id:
                return jsonify({'error': 'day_not_active'}), 403
            loc = db.execute(
                'SELECT l.name, l.day_active, m.username FROM locations l LEFT JOIN managers m ON m.location_id=l.id WHERE l.id=?',
                (location_id,)).fetchone()
            if not loc or not loc['day_active']:
                return jsonify({'error': 'day_not_active'}), 403
            location_name = loc['name']
            manager_name  = loc['username'] if loc['username'] else w['manager']
            db.execute('UPDATE workers SET working=1, clock_start=?, current_location_id=? WHERE id=?',
                       (now, location_id, wid))
            db.execute('INSERT INTO logs VALUES (?,?,?,?,?,NULL,NULL,0,0,NULL,?,?,0)',
                       (uid(), wid, w['name'], manager_name, now, location_id, location_name))
            return jsonify({'status': 'in'})
        else:
            ot_approved = 1 if w['overtime_active'] else 0
            db.execute('UPDATE workers SET working=0, clock_start=NULL, current_location_id=NULL, overtime_active=0 WHERE id=?', (wid,))
            log = db.execute(
                'SELECT * FROM logs WHERE worker_id=? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1',
                (wid,)).fetchone()
            if log:
                dur = now - log['clock_in']
                overtime = 1 if dur > shift_ms else 0
                db.execute('UPDATE logs SET clock_out=?, duration_ms=?, overtime=?, overtime_approved=? WHERE id=?',
                           (now, dur, overtime, ot_approved, log['id']))
            return jsonify({'status': 'out'})

@app.route('/api/workers/<wid>/overtime', methods=['POST', 'OPTIONS'])
def toggle_overtime(wid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    with get_db() as db:
        w = db.execute('SELECT * FROM workers WHERE id=?', (wid,)).fetchone()
        if not w: return jsonify({'error': 'not found'}), 404
        if not w['working']: return jsonify({'error': 'not_working'}), 400
        loc_id = w['current_location_id']
        # only the manager of this worker's location (or admin) may toggle
        if not s['is_admin'] and s['location_id'] != loc_id:
            return jsonify({'error': 'forbidden'}), 403
        active = (request.json or {}).get('active')
        if active is None:
            active = not w['overtime_active']  # toggle
        else:
            active = bool(active)
        db.execute('UPDATE workers SET overtime_active=? WHERE id=?', (1 if active else 0, wid))
    return jsonify({'ok': True, 'overtime_active': active})

@app.route('/api/workers/<wid>/note', methods=['POST', 'OPTIONS'])
def save_worker_note(wid):
    if request.method == 'OPTIONS': return '', 200
    note = (request.json or {}).get('note', '').strip()
    with get_db() as db:
        db.execute('UPDATE workers SET note=? WHERE id=?', (note, wid))
    return jsonify({'ok': True})

@app.route('/api/workers/<wid>/request_ot', methods=['POST'])
def request_ot(wid):
    with get_db() as db:
        log = db.execute(
            'SELECT * FROM logs WHERE worker_id=? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1',
            (wid,)).fetchone()
        if not log: return jsonify({'error': 'not_working'}), 400
        db.execute('UPDATE logs SET overtime_requested=1 WHERE id=?', (log['id'],))
    return jsonify({'ok': True})

@app.route('/api/workers/<wid>/forceout', methods=['POST'])
def force_clockout(wid):
    with get_db() as db:
        w = db.execute('SELECT * FROM workers WHERE id=?', (wid,)).fetchone()
        if not w or not w['working']: return jsonify({'ok': True})
        now = int(time.time() * 1000)
        shift_ms = float(get_setting('shift_hours') or 8) * 3600000
        ot_approved = 1 if w['overtime_active'] else 0
        db.execute('UPDATE workers SET working=0, clock_start=NULL, current_location_id=NULL, overtime_active=0 WHERE id=?', (wid,))
        log = db.execute(
            'SELECT * FROM logs WHERE worker_id=? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1',
            (wid,)).fetchone()
        if log:
            dur = now - log['clock_in']
            overtime = 1 if dur > shift_ms else 0
            db.execute('UPDATE logs SET clock_out=?, duration_ms=?, overtime=?, overtime_approved=? WHERE id=?',
                       (now, dur, overtime, ot_approved, log['id']))
    return jsonify({'ok': True})

# ── Day open/close ─────────────────────────────────────────────────────────
@app.route('/api/day/open', methods=['POST'])
def day_open():
    s, err = require_auth(request)
    if err: return err
    loc_id = (request.json or {}).get('location_id')
    if not loc_id: return jsonify({'error': 'location_id required'}), 400
    if not s['is_admin'] and s['location_id'] != loc_id:
        return jsonify({'error': 'forbidden'}), 403
    with get_db() as db:
        db.execute('UPDATE locations SET day_active=1 WHERE id=?', (loc_id,))
    return jsonify({'ok': True})

@app.route('/api/day/close', methods=['POST'])
def day_close():
    s, err = require_auth(request)
    if err: return err
    d = request.json or {}
    loc_id = d.get('location_id')
    if not loc_id: return jsonify({'error': 'location_id required'}), 400
    if not s['is_admin'] and s['location_id'] != loc_id:
        return jsonify({'error': 'forbidden'}), 403
    ot_approved_ids = set(d.get('overtime_approved', []))
    with get_db() as db:
        db.execute('UPDATE locations SET day_active=0 WHERE id=?', (loc_id,))
        # Workers with overtime_active stay clocked in — manager closes them manually
        active = db.execute('SELECT * FROM workers WHERE working=1 AND current_location_id=? AND overtime_active=0', (loc_id,)).fetchall()
        now = int(time.time() * 1000)
        shift_ms = float(get_setting('shift_hours') or 8) * 3600000
        for w in active:
            db.execute('UPDATE workers SET working=0, clock_start=NULL, current_location_id=NULL WHERE id=?', (w['id'],))
            log = db.execute(
                'SELECT * FROM logs WHERE worker_id=? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1',
                (w['id'],)).fetchone()
            if log:
                dur = now - log['clock_in']
                overtime = 1 if dur > shift_ms else 0
                ot_approved = 1 if (w['id'] in ot_approved_ids or w['overtime_active']) else 0
                db.execute('UPDATE logs SET clock_out=?, duration_ms=?, overtime=?, overtime_approved=? WHERE id=?',
                           (now, dur, overtime, ot_approved, log['id']))
    return jsonify({'ok': True})

# ── Logs ───────────────────────────────────────────────────────────────────
@app.route('/api/logs', methods=['GET'])
def get_logs():
    location_id = request.args.get('location_id')
    with get_db() as db:
        if location_id:
            rows = db.execute('SELECT * FROM logs WHERE location_id=? ORDER BY clock_in DESC LIMIT 300',
                              (location_id,)).fetchall()
        else:
            rows = db.execute('SELECT * FROM logs ORDER BY clock_in DESC LIMIT 300').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/logs/<lid>', methods=['PUT', 'OPTIONS'])
def edit_log(lid):
    if request.method == 'OPTIONS': return '', 200
    d = request.json or {}
    with get_db() as db:
        log = db.execute('SELECT * FROM logs WHERE id=?', (lid,)).fetchone()
        if not log: return jsonify({'error': 'Not found'}), 404
        new_worker_id   = d.get('worker_id',   log['worker_id'])
        new_worker_name = d.get('worker_name', log['worker_name'])
        new_manager     = d.get('manager',     log['manager'])
        new_clock_in    = d.get('clock_in',    log['clock_in'])
        new_clock_out   = d.get('clock_out',   log['clock_out'])
        ot_approved     = d.get('overtime_approved', log['overtime_approved'])
        ot_note         = d.get('overtime_note',     log['overtime_note'])
        new_loc_id      = d.get('location_id',  log['location_id'])
        new_loc_name    = d.get('location_name', log['location_name'])
        if new_loc_id and new_loc_id != log['location_id']:
            loc = db.execute('SELECT name FROM locations WHERE id=?', (new_loc_id,)).fetchone()
            if loc: new_loc_name = loc['name']
        dur = None; shift_ms = float(get_setting('shift_hours') or 8) * 3600000; overtime = 0
        if new_clock_in and new_clock_out:
            dur = int(new_clock_out) - int(new_clock_in)
            overtime = 1 if dur > shift_ms else 0
        db.execute('''UPDATE logs SET worker_id=?, worker_name=?, manager=?,
                      clock_in=?, clock_out=?, duration_ms=?, overtime=?,
                      overtime_approved=?, overtime_note=?, location_id=?, location_name=?
                      WHERE id=?''',
                   (new_worker_id, new_worker_name, new_manager,
                    new_clock_in, new_clock_out, dur, overtime,
                    ot_approved, ot_note, new_loc_id, new_loc_name, lid))
        if new_worker_id != log['worker_id'] and not log['clock_out']:
            db.execute('UPDATE workers SET working=0, clock_start=NULL, current_location_id=NULL WHERE id=?',
                       (log['worker_id'],))
    return jsonify({'ok': True})

@app.route('/api/logs/<lid>', methods=['DELETE', 'OPTIONS'])
def delete_log(lid):
    if request.method == 'OPTIONS': return '', 200
    with get_db() as db:
        log = db.execute('SELECT * FROM logs WHERE id=?', (lid,)).fetchone()
        if log and not log['clock_out']:
            db.execute('UPDATE workers SET working=0, clock_start=NULL, current_location_id=NULL WHERE id=?',
                       (log['worker_id'],))
        db.execute('DELETE FROM logs WHERE id=?', (lid,))
    return jsonify({'ok': True})

# ── Report ─────────────────────────────────────────────────────────────────
@app.route('/api/report')
def report():
    month       = int(request.args.get('month', time.localtime().tm_mon))
    year        = int(request.args.get('year',  time.localtime().tm_year))
    location_id = request.args.get('location_id')
    with get_db() as db:
        if location_id:
            logs = db.execute('SELECT * FROM logs WHERE clock_out IS NOT NULL AND location_id=?',
                              (location_id,)).fetchall()
        else:
            logs = db.execute('SELECT * FROM logs WHERE clock_out IS NOT NULL').fetchall()
        worker_notes = {r['id']: r['note'] or '' for r in db.execute('SELECT id, note FROM workers').fetchall()}
    result = {}
    for l in [dict(r) for r in logs]:
        d = datetime.datetime.fromtimestamp(l['clock_in'] / 1000)
        if d.month != month or d.year != year: continue
        wid = l['worker_id']
        if wid not in result:
            result[wid] = {'name': l['worker_name'], 'manager': l['manager'],
                           'location': l.get('location_name') or '—',
                           'note': worker_notes.get(wid, ''),
                           'total_ms': 0, 'sessions': 0, 'overtime_sessions': 0}
        result[wid]['total_ms']          += l['duration_ms'] or 0
        result[wid]['sessions']          += 1
        result[wid]['overtime_sessions'] += 1 if l['overtime'] else 0
    return jsonify(sorted(result.values(), key=lambda x: -x['total_ms']))

# ── AI Reports ────────────────────────────────────────────────────────────
MONTH_NAMES = {
    'he': ['ינואר','פברואר','מרץ','אפריל','מאי','יוני','יולי','אוגוסט','ספטמבר','אוקטובר','נובמבר','דצמבר'],
    'en': ['January','February','March','April','May','June','July','August','September','October','November','December'],
    'ar': ['يناير','فبراير','مارس','أبريل','مايو','يونيو','يوليو','أغسطس','سبتمبر','أكتوبر','نوفمبر','ديسمبر'],
}
LANG_NAMES = {'he': 'Hebrew', 'en': 'English', 'ar': 'Arabic'}

def _collect_report_data(month, year):
    """Return per-worker stats for the given month/year."""
    with get_db() as db:
        logs = db.execute('SELECT * FROM logs WHERE clock_out IS NOT NULL').fetchall()
        workers_rows = db.execute('SELECT id, name, note FROM workers').fetchall()
    notes = {r['id']: r['note'] or '' for r in workers_rows}
    result = {}
    for l in [dict(r) for r in logs]:
        d = datetime.datetime.fromtimestamp(l['clock_in'] / 1000)
        if d.month != month or d.year != year: continue
        wid = l['worker_id']
        if wid not in result:
            result[wid] = {'worker_id': wid, 'name': l['worker_name'], 'manager': l['manager'],
                           'total_ms': 0, 'sessions': 0, 'overtime_sessions': 0,
                           'note': notes.get(wid, '')}
        result[wid]['total_ms']          += l['duration_ms'] or 0
        result[wid]['sessions']          += 1
        result[wid]['overtime_sessions'] += 1 if l['overtime'] else 0
    return list(result.values())

def _generate_one_report(worker_data, month, year, lang='he'):
    api_key = get_setting('anthropic_api_key') or os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        raise ValueError('No Anthropic API key configured.')
    try:
        import anthropic as ac
    except ImportError:
        raise ValueError('anthropic package not installed.')

    month_name = MONTH_NAMES.get(lang, MONTH_NAMES['en'])[month - 1]
    lang_name  = LANG_NAMES.get(lang, 'Hebrew')
    total_hours = worker_data['total_ms'] / 3600000
    note_text = worker_data['note'] or 'No notes from manager.'

    prompt = (
        f"Write a professional monthly work summary report in {lang_name} for the following employee. "
        f"The report should be warm, professional, and suitable for HR records. "
        f"It should be 2-3 paragraphs covering attendance, overtime (if any), and any relevant observations from the manager's notes.\n\n"
        f"Employee: {worker_data['name']}\n"
        f"Month: {month_name} {year}\n"
        f"Total hours worked: {total_hours:.1f} hours\n"
        f"Number of shifts: {worker_data['sessions']}\n"
        f"Overtime shifts: {worker_data['overtime_sessions']}\n"
        f"Manager: {worker_data['manager']}\n"
        f"Manager notes: {note_text}\n\n"
        f"Write only the report body, no title or header."
    )

    client = ac.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model='claude-sonnet-4-6',
        max_tokens=1024,
        messages=[{'role': 'user', 'content': prompt}]
    )
    return msg.content[0].text

def generate_reports_for_month(month, year, lang='he'):
    """Generate and store AI reports for all workers for the given month."""
    workers_data = _collect_report_data(month, year)
    errors = []
    for wd in workers_data:
        try:
            content = _generate_one_report(wd, month, year, lang)
            rid = uid()
            with get_db() as db:
                # replace existing report for same worker/month/year
                db.execute('DELETE FROM reports WHERE worker_id=? AND month=? AND year=?',
                           (wd['worker_id'], month, year))
                db.execute('INSERT INTO reports VALUES (?,?,?,?,?,?,?)',
                           (rid, wd['worker_id'], wd['name'], month, year,
                            content, int(time.time() * 1000)))
        except Exception as e:
            errors.append(f"{wd['name']}: {e}")
    return errors

def _month_end_scheduler():
    """Background thread — generates reports on the 1st of each month for the previous month."""
    last_triggered = None
    while True:
        threading.Event().wait(3600)  # check every hour
        now = datetime.datetime.now()
        key = (now.year, now.month)
        if now.day == 1 and last_triggered != key:
            prev = (now.replace(day=1) - datetime.timedelta(days=1))
            try:
                lang = get_setting('report_lang') or 'he'
                generate_reports_for_month(prev.month, prev.year, lang)
            except Exception:
                pass
            last_triggered = key

@app.route('/api/reports', methods=['GET'])
def list_reports():
    s, err = require_auth(request)
    if err: return err
    with get_db() as db:
        rows = db.execute(
            'SELECT id, worker_id, worker_name, month, year, generated_at FROM reports ORDER BY year DESC, month DESC, worker_name').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/reports/<rid>', methods=['GET'])
def get_report(rid):
    s, err = require_auth(request)
    if err: return err
    with get_db() as db:
        row = db.execute('SELECT * FROM reports WHERE id=?', (rid,)).fetchone()
    if not row: return jsonify({'error': 'not found'}), 404
    return jsonify(dict(row))

@app.route('/api/reports/generate', methods=['POST', 'OPTIONS'])
def trigger_generate():
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    d = request.json or {}
    now = datetime.datetime.now()
    month = int(d.get('month', now.month))
    year  = int(d.get('year',  now.year))
    lang  = d.get('lang', get_setting('report_lang') or 'he')
    set_setting('report_lang', lang)
    errors = generate_reports_for_month(month, year, lang)
    return jsonify({'ok': True, 'errors': errors})

@app.route('/api/reports/<rid>', methods=['DELETE', 'OPTIONS'])
def delete_report(rid):
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    with get_db() as db:
        db.execute('DELETE FROM reports WHERE id=?', (rid,))
    return jsonify({'ok': True})

@app.route('/api/settings/apikey', methods=['POST', 'OPTIONS'])
def save_api_key():
    if request.method == 'OPTIONS': return '', 200
    s, err = require_auth(request)
    if err: return err
    if not s['is_admin']: return jsonify({'error': 'admin_only'}), 403
    key = (request.json or {}).get('key', '').strip()
    set_setting('anthropic_api_key', key)
    return jsonify({'ok': True})

# ── Static / PWA ───────────────────────────────────────────────────────────
@app.route('/sw.js')
def sw(): return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/manifest-worker.json')
def manifest_worker(): return send_from_directory('static', 'manifest-worker.json', mimetype='application/json')

@app.route('/manifest-manager.json')
def manifest_manager(): return send_from_directory('static', 'manifest-manager.json', mimetype='application/json')

@app.route('/icons/<path:f>')
def icons(f): return send_from_directory('static/icons', f)

@app.route('/')
@app.route('/worker')
def worker_page(): return send_from_directory('static', 'worker.html')

@app.route('/manager')
def manager_page(): return send_from_directory('static', 'manager.html')

if __name__ == '__main__':
    init_db()
    t = threading.Thread(target=_month_end_scheduler, daemon=True)
    t.start()
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); local_ip = s.getsockname()[0]; s.close()
    except: local_ip = '127.0.0.1'
    port = int(os.environ.get('PORT', 5050))
    print(f'\nWorkTrack running → http://{local_ip}:{port}')
    app.run(host='0.0.0.0', port=port, debug=False)
