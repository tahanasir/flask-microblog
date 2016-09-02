# all the imports
import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
	render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash

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

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('SELECT user_id FROM users where username = ?', 
                [username], one=True)
    return rv[0] if rv else None

def edit_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    cur.close()

@app.route('/')
def home():
    return render_template('layout.html')

@app.route('/<user>')
def show_entries(user):
    entries = query_db('SELECT title, text FROM entries where entries.author = ? ORDER BY id DESC ', [user])
    return render_template('show_entries.html', entries=entries, user=user)

@app.route('/add', methods=['POST'])
def add_entry():
    if 'username' not in session:
        abort(401)
    edit_db('INSERT INTO entries (author, title, text) VALUES (?, ?, ?)', 
            [session['username'], request.form['title'], request.form['text']])
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries', user=session['username']))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = query_db('SELECT * FROM users where username = ?', 
                        [request.form['username']], one=True)

        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            session['username'] = user['username']
            flash('You were logged in')
            return redirect(url_for('show_entries', user=user['username']))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You were logged out')
    return redirect(url_for('home'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'Please enter a username'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'Please enter a valid email address'
        elif not request.form['password']:
            error = 'Please enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'Passwords do no match'
        else:
            edit_db('INSERT INTO users (username, email, pw_hash) VALUES (?, ?, ?)', 
                    [request.form['username'], request.form['email'], \
                    generate_password_hash(request.form['password'])])
            flash('Your account was successfully registered')
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)
 

