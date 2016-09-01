# all the imports
import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
	render_template, flash

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)

# Load default config and override config from an environment variable
mydict = dict(
    DATABASE=os.path.join(app.root_path, 'blog.db'),
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='password',
)

app.config.update(mydict)
app.config.from_envvar('BLOG_SETTINGS', silent=True)

def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    conn = g.get('sqlite_db', None)
    if conn is None:
        conn = g.sqlite_db = connect_db()
    return conn

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    conn = g.get('sqlite_db', None)
    if conn is not None:
        conn.close()

def init_db():
    conn = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        cur = conn.cursor()
        cur.executescript(f.read())
    conn.commit()

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()
    print ('Initialized the database.')

@app.route('/')
def show_entries():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT title, text FROM ENTRIES ORDER BY id DESC')
    entries = cur.fetchall()
    cur.close()
    return render_template('show_entries.html', entries=entries)

@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT INTO entries (title, text) VALUES (?, ?)', 
                    [request.form['title'], request.form['text']])
    conn.commit()
    cur.close()
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('show_entries'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))
