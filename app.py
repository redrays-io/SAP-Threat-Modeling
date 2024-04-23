import sqlite3
from flask import Flask, request, render_template, jsonify
from sap_utils.scanning.scan import scan_systems

app = Flask(__name__)

# Constants
DB_FILE = "db.sqlite"


# Database initialization
def initialize_database(db_file):
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()

        # Create credentials table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            sid TEXT,
                            client TEXT,
                            host TEXT,
                            port TEXT,
                            use_https INTEGER,
                            username TEXT,
                            password TEXT
                        )''')

        # Create sap_connections table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS sap_connections (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            connection_name TEXT,
                            connection_type TEXT,
                            connection_from TEXT,
                            connection_to TEXT,
                            username TEXT,
                            password_flag BOOLEAN
                        )''')


# Initialize the database
initialize_database(DB_FILE)


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/remove_connection', methods=['POST'])
def remove_connection():
    data = request.get_json()
    print(data)
    sid = data['sid']
    host = data['host']
    port = data['port']

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''DELETE FROM credentials WHERE sid = ? AND host = ? AND port = ?''', (sid, host, port))
        conn.commit()

    return jsonify({'message': 'Connection removed successfully!'})


@app.route('/launchpad')
def launchpad():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT sid, username, password, client, use_https, host, port FROM credentials''')
        connections = cursor.fetchall()

    return render_template('launchpad.html', connections=connections)


@app.route('/connectionsTable')
def connectionsTable():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM sap_connections''')
        connections = cursor.fetchall()

    return render_template('connectionsTable.html', connections=connections)


@app.route('/threatMap')
def threatMap():
    return render_template('threatMap.html')


@app.route('/save_data', methods=['POST'])
def save_data():
    data_list = request.get_json()

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        for data in data_list:
            cursor.execute('''INSERT INTO credentials (sid, client, host, port, use_https, username, password)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (
                           data['sid'], data['client'], data['host'], data['port'], data['use_https'], data['username'],
                           data['password']))
        conn.commit()

    return jsonify({'message': 'Data saved successfully!'})


@app.route('/scan', methods=['GET'])
def scan():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT sid, client, host, port, use_https, username, password FROM credentials''')
        credentials = cursor.fetchall()
        cursor.execute('''DELETE FROM sap_connections''')

        sap_connection_array = []
        for credential in credentials:
            sap_connection_array.append({
                'sid': credential[0],
                'client': credential[1],
                'host': credential[2],
                'port': credential[3],
                'use_https': credential[4],
                'username': credential[5],
                'password': credential[6],
            })
        for sap_connection in sap_connection_array:
                scan_result_list = scan_systems(sap_connection['host'], sap_connection['port'],
                                                sap_connection['client'], sap_connection['username'],
                                                sap_connection['password'], sap_connection['use_https'])
                for scan_result in scan_result_list:
                    cursor.execute('''INSERT INTO sap_connections 
                                     (connection_name, connection_type, connection_from, connection_to, username, password_flag)
                                     VALUES (?, ?, ?, ?, ?, ?)''',
                                   (scan_result.connection_name, scan_result.connection_type,
                                    scan_result.connection_from, scan_result.connection_to, scan_result.username,
                                    scan_result.password_flag))
                    print(scan_result)
        conn.commit()

    return jsonify('')


@app.route('/get_connections')
def get_connections():
    try:
        password_only = request.args.get('password_only')

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if password_only and password_only.lower() == 'true':
                cursor.execute(
                    '''SELECT connection_from, connection_to, connection_name FROM sap_connections WHERE password_flag = 1''')
            else:
                cursor.execute('''SELECT connection_from, connection_to, connection_name FROM sap_connections''')
            connections = cursor.fetchall()

        connection_data = [
            {'connection_from': connection[0], 'connection_to': connection[1], 'connection_name': connection[2]} for
            connection in connections]
        return jsonify(connection_data)
    except Exception as e:
        return jsonify({'error': str(e)})


if __name__ == '__main__':
    app.run(debug=True)
