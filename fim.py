#FILE INTEGRETY MONITOR © 2020, cyberlabperm
#Released under GNU GPL v3 license 
from pathlib import Path
import configparser, time, hashlib, os, rsa

#configuration commands
def set_mode(section, option, new_value):
    config = configparser.ConfigParser()
    with open('config.ini') as file:
        config.read_file(file)
    config.set(f"{section}", f'{option}', f'{new_value}')
    with open('config.ini', 'w') as file:
        config.write(file)    

def load_main_config():
    settings = dict()
    config = configparser.ConfigParser()
    config.read("config.ini")
    sections = config.sections()
    for section in sections:
        if section != 'FILE_LIST':
            options = config.options(section)
            for option in options:
                settings[option]=config.get(section, option)
    if settings.get('use_db') == 'mysql':
        import pymysql
    elif settings.get('use_db') == 'sqlite3':
        import sqlite3
    return settings

def load_file_config():    
    file_settings = dict()
    config = configparser.ConfigParser()
    config.read("config.ini")
    directories = config.items('FILE_LIST')    
    for setting in directories:
        file_settings[f'{setting[0]}'] = (config.get('FILE_LIST',f'{setting[0]}').splitlines())
    return file_settings

#Methods for creating list of files to control
def do_file_list_dir(address):
    spisok = list()
    current_dir = Path(address)
    for current_file in current_dir.iterdir():
        if current_file.is_dir() == False:
            spisok.append(str(current_file))        
    return spisok

def do_file_list_all(address):
    spisok = list()
    for top, dirs, files in os.walk(address):
        for nm in files:
            spisok.append(os.path.join(top,nm))
    return spisok

def do_file_list_filtr(address, filtr):
    spisok = list()
    current_dir = Path(address)    
    for current_file in current_dir.glob(filtr):
        spisok.append(str(current_file))
    return spisok

def create_file_list():
    file_list = list()
    file_settings = load_file_config()
    for item in file_settings.get('dir_check_all'):
        for file in do_file_list_all(item):
            file_list.append(file)

    for item in file_settings.get('dir_check_files'): 
        for file in do_file_list_dir(item):
            file_list.append(file)
           
    for i in range(0, len(file_settings.get('dir_check_filtr'))):
        path = file_settings.get('dir_check_filtr')[i]
        filtr = file_settings.get('filtr')[i].replace(',', '')    
        for f in filtr.split():
            for file in do_file_list_filtr(path, f):
                file_list.append(file)
    return file_list

def load_file_list(settings):
    file_list = list()
    temp_file_list = create_file_list()
    if (settings.get('use_db') == 'mysql') or (settings.get('use_db') == 'sqlite3'):
        conn = connect_to_db(settings)
        cur = conn.cursor()
        command = f"SELECT path FROM checklist"
        cur.execute(command)
        files = cur.fetchall()
        for file in files:
            if file[0] not in temp_file_list:
                print(f'{file[0]} was deleted hash cannot be checked!!')
            else:
                file_list.append(file[0])
    else:
        config = configparser.ConfigParser()
        path = settings.get('service_folder')
        config.read(path+"sys_config.ini")
        control_point = settings.get('control_point')
        files = config.options(control_point)  
        for file in files:
            if file not in temp_file_list:
                print(f'{file} was deleted hash cannot be checked!!')
            else:
                file_list.append(file) 
    return file_list


#Methods of file digest
def get_hash(file, hash_type):
    hsh = hashlib.new(hash_type)
    for data in file:        	
        if not data:
            data = b''
        hsh.update(data)
    return hsh.hexdigest()
    
def do_digest_hash(file_list, hash_type):
    check = list()
    for i in range(0,len(file_list)):        
        with open(file_list[i], 'rb') as file:            
            hsh = get_hash(file, hash_type)        
        digest = file_list[i], hsh
        check.append(digest)
    return check    

def do_digest_rsa(file_list, hash_type, PVKey):    
    check = list()
    for i in range(0,len(file_list)):
        with open(file_list[i], 'rb') as file:            
            hsh = get_hash(file, hash_type)
        hash_sign = rsa.sign(hsh.encode('utf-8'), PVKey, 'MD5')
        digest = file_list[i], hash_sign.hex()
        check.append(digest)    
    return check

#Methods to save data in db
def connect_to_db(settings):    
    if settings.get('use_db') == 'mysql':
        import pymysql
        conn = pymysql.connect(host=settings.get('mysql_server'),
                               user=settings.get('mysql_user'),
                               password=settings.get('mysql_password'),
                               db = settings.get('mysql_db'))
    elif settings.get('use_db') == 'sqlite3':
        import sqlite3
        conn = sqlite3.connect(settings.get('service_folder')+settings.get('sqllite_db')) 
    return conn

def create_table(conn):
    conn.cursor().execute('CREATE TABLE IF NOT EXISTS checklist(path TEXT, hash TEXT, time TEXT);')
    conn.commit()
    
def insert_in_db(conn, values, event_time):
    cur = conn.cursor()
    command = f"INSERT INTO checklist (path, hash, time) VALUES ('{str(values[0])}', '{str(values[1])}','{str(event_time)}' )"
    cur.execute(command)
    conn.commit()

def save_digest_to_db(conn, check_list, event_time):
    for checksum in check_list:
        insert_in_db(conn, checksum, event_time)
    set_mode('MAIN', 'control_point', f'{event_time}')

#methods to save digest in file
def save_digest_list(digest_list, path):
    print('start saving')
    with open(path+'sys_config.ini', 'a') as sys_config:
        event_time = time.strftime("%d-%m-%Y %H.%M.%S", time.localtime())
        sys_config.write(f'[{event_time}]\n')
        for digest in digest_list:
            sys_config.write(digest[0] + '=' + digest[1]+'\n')
        sys_config.close()
        set_mode('MAIN', 'control_point', f'{event_time}')
        print('digest list is saved')

#methods for RSA encryption
def create_rsa_keys(settings):
    PB, PV = rsa.newkeys(2048)
    save_key(PV, 'private', settings.get('pv_key'))
    save_key(PB, 'public', settings.get('pb_key'))

def save_key(key, key_type, path):
    config = configparser.ConfigParser()
    config.add_section("RSA")
    config.set("RSA", 'n', f'{key.n}')
    config.set("RSA", 'e', f'{key.e}')
    if key_type == 'private':
        config.set("RSA", 'd', f'{key.d}')
        config.set("RSA", 'p', f'{key.p}')
        config.set("RSA", 'q', f'{key.q}')
    with open(f'{path}', 'w') as file:
        config.write(file)  

def load_key(path, key_type):
    k = dict()
    key = configparser.ConfigParser()
    key.read(f"{path}")
    sections = key.sections()
    for section in sections:        
        options = key.options(section)
        for option in options:            
            k[option]=int(key.get(section, option))
    if key_type == 'pv_key':
        rsa_key = rsa.PrivateKey(k.get('n'), k.get('e'), k.get('d'), k.get('p'),k.get('q'))  
    elif key_type == 'pb_key':
        rsa_key = rsa.PublicKey(k.get('n'), k.get('e'))
    return rsa_key

def verify_digest(settings, digest, check):    
    if settings.get('digest_type') == 'hash':
        if digest[1] == check:
            check_status = True
        else:
            check_status = False
    elif settings.get('digest_type') == 'rsa':       
        pb_key = load_key(settings.get('pb_key' ), 'pb_key' )
        msg = bytes.fromhex(check)
        try:
            rsa.verify(digest[1].encode(), msg, pb_key)
            check_status = True
        except BaseException:
            check_status = False
    return check_status

    
def return_status(check_status, digest):
    if check_status == True: 
        print(f'hash for {digest[0]} is valid')
    else:
        print(f'DANGER!!! HASH FOR {digest[0]} IS NOT VALID!!!')
    
#Methods to control current file list
def verify_digest_list(settings, digest_list):
    if (settings.get('use_db') == 'mysql') or (settings.get('use_db') == 'sqlite3'):
        conn = connect_to_db(settings)
        cur = conn.cursor()
    else:
        config = configparser.ConfigParser()
        path = settings.get('service_folder')
        config.read(path+"sys_config.ini")
        control_point = settings.get('control_point')
    for digest in digest_list:
        if (settings.get('use_db') == 'mysql') or (settings.get('use_db') == 'sqlite3'):
            command = f"SELECT hash FROM checklist WHERE path='{digest[0]}'"
            cur.execute(command)
            result = cur.fetchone()
            check = result[0]
        else:
            check = config.get(control_point, f'{digest[0]}')
        check_status = verify_digest(settings, digest, check)
        return_status(check_status, digest)


