#FILE INTEGRETY MONITOR: MANAGER© 2020, cyberlabperm
#Released under GNU GPL v3 license

#module to create controlled file list
import fim, time
print('load settings... please wait')
settings = fim.load_main_config()
print('settings loaded.')

## mode = init - initial start, create file list and digest 
def generate_keys():
    fim.create_rsa_keys(settings)

def digest_init(settings):
    if settings.get('mode') == 'init':
        files = fim.create_file_list()
    elif settings.get('mode') == 'check':
        files = fim.load_file_list(settings)
    hash_type = settings.get('hash')
    if settings.get('digest_type') == 'hash' or settings.get('mode') != 'init':        
        digest_list = fim.do_digest_hash(files, hash_type)
    else:
        key_type = 'pv_key'
        pv_key = fim.load_key(settings.get(key_type), key_type)
        digest_list = fim.do_digest_rsa(files, hash_type, pv_key)
    return digest_list

def fim_init(settings):
    print('start initialization')   
    digest_list = digest_init(settings)            
    if (settings.get('use_db') == 'mysql') or (settings.get('use_db') == 'sqlite3'):
        conn = fim.connect_to_db(settings)
        fim.create_table(conn)
        event_time = time.strftime("%d-%m-%Y %H.%M.%S", time.localtime())
        fim.save_digest_to_db(conn, digest_list, event_time)
    else:
        path = settings.get('service_folder')
        fim.save_digest_list(digest_list, path)
    fim.set_mode('MAIN', 'mode', 'check')

def fim_check(settings):
    temp_digest = digest_init(settings)    
    fim.verify_digest_list(settings, temp_digest)


if settings.get('mode') == 'init':
    fim_init(settings)
elif settings.get('mode') == 'check':
    fim_check(settings)

