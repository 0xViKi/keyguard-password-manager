#!/usr/bin/python3

__author__ = "0xViKi"
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "0xViKi"
__status__ = "Production"

import sqlite3
from sqlite3 import Error
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import random
from tabulate import tabulate
from hashlib import md5
import shutil

# * Important Stuff
masterKey = b'FX\x12\xe9W\x12d\xfc]\xf6\x86\x81\xba\xa9G\xe3\xd3\x99)\x9cC\xa4\xb4\xc3\x10\xe1\xcc-\x90\x94&\xa6'
masterIV = b'\xe1\xa2u|q\\\xa6\x17p.\xb6\x92\xce\xc1\xfe\x92'

# Recovery word list 

recWordList = ['aah', 'aal', 'aas', 'aba', 'abs', 'aby', 'ace', 'act', 'add', 'ado', 'ads', 'adz', 'aff', 'aft', 'aga', 'age', 'ago', 'aha', 'ahi', 'ahs', 'aid', 'ail', 'aim', 'ain', 'air', 'ais', 'ait', 'ala', 'alb', 'ale', 'all', 'alp', 'als', 'alt', 'ama', 'ami', 'amp', 'amu', 'ana', 'and', 'ane', 'ani', 'ant', 'any', 'ape', 'app', 'apt', 'arb', 'arc', 'are', 'arf', 'ark', 'arm', 'ars', 'art', 'ash', 'ask', 'asp', 'ass', 'ate', 'att', 'auk', 'ava', 'ave', 'avo', 'awa', 'awe', 'awl', 'awn', 'axe', 'aye', 'ays', 'azo', 'baa', 'bad', 'bag', 'bah', 'bal', 'bam', 'ban', 'bap', 'bar', 'bas', 'bat', 'bay', 'bed', 'bee', 'beg', 'bel', 'ben', 'bet', 'bey', 'bib', 'bid', 'big', 'bin', 'bio', 'bis', 'bit', 'biz', 'boa', 'bob', 'bod', 'bog', 'boo', 'bop', 'bos', 'bot', 'bow', 'box', 'boy', 'bra', 'bro', 'brr', 'bub', 'bud', 'bug', 'bum', 'bun', 'bur', 'bus', 'but', 'buy', 'bye', 'bys', 'cab', 'cad', 'cam', 'can', 'cap', 'car', 'cat', 'caw', 'cay', 'cee', 'cel', 'cep', 'chi', 'cig', 'cis', 'cob', 'cod', 'cog', 'col', 'con', 'coo', 'cop', 'cor', 'cos', 'cot', 'cow', 'cox', 'coy', 'coz', 'cru', 'cry', 'cub', 'cud', 'cue', 'cup', 'cur', 'cut', 'cwm', 'dab', 'dad', 'dag', 'dah', 'dak', 'dal', 'dam', 'dan', 'dap', 'daw', 'day', 'deb', 'dee', 'def', 'del', 'den', 'dev', 'dew', 'dex', 'dey', 'dib', 'did', 'die', 'dif', 'dig', 'dim', 'din', 'dip', 'dis', 'dit', 'doc', 'doe', 'dog', 'doh', 'dol', 'dom', 'don', 'dor', 'dos', 'dot', 'dow', 'dry', 'dub', 'dud', 'due', 'dug', 'duh', 'dui', 'dum', 'dun', 'duo', 'dup', 'dye', 'ear', 'eat', 'eau', 'ebb', 'eco', 'ecu', 'edh', 'eek', 'eel', 'eff', 'efs', 'eft', 'egg', 'ego', 'eke', 'eld', 'elf', 'elk', 'ell', 'elm', 'els', 'eme', 'emo', 'ems', 'emu', 'end', 'eng', 'ens', 'eon', 'era', 'ere', 'erg', 'ern', 'err', 'ers', 'ess', 'eta', 'eth', 'eve', 'ewe', 'eye', 'fab', 'fad', 'fah', 'fan', 'far', 'fas', 'fat', 'fax', 'fay', 'fed', 'fee', 'feh', 'fem', 'fen', 'fer', 'fet', 'feu', 'few', 'fey', 'fez', 'fib', 'fid', 'fie', 'fig', 'fil', 'fin', 'fir', 'fit', 'fix', 'fiz', 'flu', 'fly', 'fob', 'foe', 'fog', 'foh', 'fon', 'foo', 'fop', 'for', 'fou', 'fox', 'foy', 'fro', 'fry', 'fub', 'fud', 'fug', 'fun', 'fur', 'gab', 'gad', 'gae', 'gag', 'gal', 'gam', 'gan', 'gap', 'gar', 'gas', 'gat', 'gay', 'ged', 'gee', 'gel', 'gem', 'gen', 'get', 'gey', 'ghi', 'gib', 'gid', 'gie', 'gig', 'gin', 'gip', 'gis', 'git', 'gnu', 'goa', 'gob', 'god', 'goo', 'gor', 'got', 'gox', 'goy', 'gul', 'gum', 'gun', 'gut', 'guv', 'guy', 'gym', 'had', 'hae', 'hag', 'hah', 'haj', 'ham', 'hao', 'hap', 'has', 'hat', 'haw', 'hay', 'heh', 'hem', 'hen', 'hep', 'her', 'hes', 'het', 'hew', 'hex', 'hey', 'hic', 'hid', 'hie', 'him', 'hin', 'hip', 'his', 'hit', 'hmm', 'hob', 'hod', 'hoe', 'hog', 'hom', 'hon', 'hop', 'hos', 'hot', 'how', 'hoy', 'hub', 'hue', 'hug', 'huh', 'hum', 'hun', 'hup', 'hut', 'hyp', 'ice', 'ich', 'ick', 'icy', 'ids', 'iff', 'ifs', 'igg', 'ilk', 'ill', 'imp', 'ink', 'inn', 'ins', 'ion', 'ire', 'irk', 'ism', 'its', 'ivy', 'jab', 'jag', 'jam', 'jar', 'jaw', 'jay', 'jee', 'jet', 'jeu', 'jib', 'jig', 'jin', 'job', 'joe', 'jog', 'jot', 'jow', 'joy', 'jug', 'jun', 'jus', 'jut', 'kab', 'kae', 'kaf', 'kas', 'kat', 'kay', 'kea', 'kef', 'keg', 'ken', 'kep', 'kex', 'key', 'khi', 'kid', 'kif', 'kin', 'kip', 'kir', 'kit', 'koa', 'kob', 'koi', 'kop', 'kor', 'kos', 'kue', 'kye', 'lab', 'lac', 'lad', 'lag', 'lah', 'lam', 'lap', 'lar', 'las', 'lat', 'lav', 'law', 'lax', 'lay', 'lea', 'led', 'lee', 'leg', 'lei', 'lek', 'let', 'leu', 'lev', 'lex', 'ley', 'lib', 'lid', 'lie', 'lin', 'lip', 'lis', 'lit', 'lob', 'log', 'loo', 'lop', 'lot', 'low', 'lox', 'lud', 'lug', 'lum', 'luv', 'lux', 'lye', 'mac', 'mad', 'mae', 'mag', 'mam', 'man', 'map', 'mar', 'mas', 'mat', 'maw', 'max', 'may', 'med', 'meg', 'meh', 'mel', 'mem', 'men', 'met', 'mew', 'mho', 'mib', 'mic', 'mid', 'mig', 'mil', 'mim', 'mir', 'mis', 'mix', 'mmm', 'moa', 'mob', 'moc', 'mod', 'mog', 'moi', 'mol', 'mom', 'mon', 'moo', 'mop', 'mor', 'mos', 'mot', 'mow', 'mud', 'mug', 'mum', 'mun', 'mus', 'mut', 'mux', 'nab', 'nae', 'nag', 'nah', 'nam', 'nan', 'nap', 'naw', 'nay', 'neb', 'nee', 'net', 'new', 'nib', 'nil', 'nim', 'nip', 'nit', 'nix', 'nob', 'nod', 'nog', 'noh', 'nom', 'noo', 'nor', 'nos', 'not', 'now', 'nth', 'nub', 'nun', 'nus', 'nut', 'obe', 'obi', 'oca', 'oaf', 'oak', 'oar', 'oat', 'oba', 'och', 'oda', 'odd', 'ode', 'ods', 'oes', 'off', 'oft', 'ohm', 'oho', 'ohs', 'oik', 'oil', 'oka', 'oke', 'old', 'ole', 'oms', 'one', 'ono', 'ons', 'oof', 'ooh', 'oot', 'ope', 'ops', 'opt', 'ora', 'orb', 'orc', 'ore', 'ors', 'ort', 'ose', 'oud', 'our', 'out', 'ova', 'owe', 'owl', 'own', 'owt', 'oxo', 'oxy', 'pac', 'pad', 'pah', 'pal', 'pam', 'pan', 'pap', 'par', 'pas', 'pat', 'paw', 'pax', 'pay', 'pea', 'pec', 'ped', 'pee', 'peg', 'peh', 'pen', 'pep', 'per', 'pes', 'pet', 'pew', 'phi', 'pho', 'pht', 'pia', 'pic', 'pie', 'pig', 'pin', 'pip', 'pis', 'pit', 'piu', 'pix', 'ply', 'pod', 'poh', 'poi', 'pol', 'pom', 'poo', 'pop', 'pos', 'pot', 'pow', 'pox', 'pro', 'pry', 'psi', 'pub', 'pud', 'pug', 'pul', 'pun', 'pup', 'pur', 'pus', 'put', 'pya', 'pye', 'pyx', 'qat', 'qis', 'qua', 'rad', 'rag', 'rah', 'rai', 'raj', 'ram', 'ran', 'rap', 'ras', 'rat', 'raw', 'rax', 'ray', 'reb', 'rec', 'red', 'ree', 'ref', 'reg', 'rei', 'rem', 'rep', 'res', 'ret', 'rev', 'rex', 'rho', 'ria', 'rib', 'rid', 'rif', 'rig', 'rim', 'rin', 'rip', 'rob', 'roc', 'rod', 'roe', 'rom', 'roo', 'rot', 'row', 'rub', 'rue', 'rug', 'rum', 'run', 'rut', 'rya', 'rye', 'ryu', 'sab', 'sac', 'sad', 'sae', 'sag', 'sal', 'san', 'sap', 'sat', 'sau', 'saw', 'sax', 'say', 'sea', 'sec', 'see', 'sei', 'sel', 'sen', 'ser', 'set', 'sev', 'sew', 'sex', 'sez', 'sha', 'she', 'shh', 'sho', 'shy', 'sib', 'sic', 'sim', 'sin', 'sip', 'sir', 'sis', 'sit', 'six', 'ska', 'ski', 'sky', 'sly', 'sob', 'soc', 'sod', 'soh', 'sol', 'som', 'son', 'sop', 'sos', 'sot', 'sou', 'sow', 'sox', 'soy', 'spa', 'spy', 'sri', 'sty', 'sub', 'sue', 'suk', 'sum', 'sun', 'sup', 'suq', 'sus', 'syn', 'tab', 'tad', 'tae', 'tag', 'taj', 'tam', 'tan', 'tao', 'tap', 'tar', 'tas', 'tat', 'tau', 'tav', 'taw', 'tax', 'tea', 'ted', 'tee', 'teg', 'tel', 'ten', 'tet', 'tew', 'the', 'tho', 'thy', 'tic', 'tie', 'til', 'tin', 'tip', 'tis', 'tit', 'tiz', 'tod', 'toe', 'tog', 'tom', 'ton', 'too', 'top', 'tor', 'tot', 'tow', 'toy', 'try', 'tsk', 'tub', 'tug', 'tui', 'tum', 'tun', 'tup', 'tut', 'tux', 'twa', 'two', 'tye', 'udo', 'ugh', 'uke', 'ulu', 'umm', 'ump', 'uni', 'uns', 'upo', 'ups', 'urb', 'urd', 'urn', 'use', 'uta', 'ute', 'uts', 'vac', 'van', 'var', 'vas', 'vat', 'vau', 'vav', 'vaw', 'vee', 'veg', 'vet', 'vex', 'via', 'vid', 'vie', 'vig', 'vim', 'vin', 'vis', 'voe', 'vog', 'vow', 'vox', 'vug', 'wab', 'wad', 'wae', 'wag', 'wan', 'wap', 'war', 'was', 'wat', 'waw', 'wax', 'way', 'web', 'wed', 'wee', 'wen', 'wet', 'wha', 'who', 'why', 'wig', 'win', 'wis', 'wit', 'wiz', 'woe', 'wok', 'won', 'woo', 'wos', 'wot', 'wow', 'wry', 'wud', 'wuz', 'wye', 'wyn', 'yag', 'yah', 'yak', 'yam', 'yap', 'yar', 'yas', 'yaw', 'yay', 'yea', 'yeh', 'yen', 'yep', 'yer', 'yes', 'yet', 'yew', 'yez', 'yin', 'yip', 'yob', 'yod', 'yok', 'yom', 'yon', 'you', 'yow', 'yuk', 'yum', 'yup', 'zag', 'zap', 'zas', 'zax', 'zed', 'zee', 'zek', 'zen', 'zig', 'zin', 'zip', 'zit', 'zoa', 'zoo', 'xis']

# * Static Variables

logo = '''+-----------------------------------------------------------------------------------+    
|                   _  _ ____ _   _    ____ _  _ ____ ____ ___                      |          
|                   |_/  |___  \_/     | __ |  | |__| |__/ |  \                     |         
|                   | \_ |___   |      |__] |__| |  | |  \ |__/                     |          
|                                                                                   |
|  ___  ____ ____ ____ _ _ _ ____ ____ ___     _  _ ____ _  _ ____ ____ ____ ____   |
|  |__] |__| [__  [__  | | | |  | |__/ |  \    |\/| |__| |\ | |__| | __ |___ |__/   |
|  |    |  | ___] ___] |_|_| |__| |  \ |__/    |  | |  | | \| |  | |__] |___ |  \   |
|                                                                                   |
+-----------------------------------------------------------------------------------+
| Author:   0xViKi                                                                  |
| Github:   https://github.com/0xViKi                                               |
| Website:  https://0xViKi.github.io                                                |
+-----------------------------------------------------------------------------------+'''

dList = ['1', '2', 'x']
uList  = ['1', '2', '3', '4', 'x']
    
# * MASTER TABLE SQL STATEMENTS

masterDbSQL = '''CREATE TABLE IF NOT EXISTS master(
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        VARCHAR(20)        NOT NULL UNIQUE,
            password        VARCHAR(30)        NOT NULL,
            recoverycode    TEXT               NOT NULL UNIQUE,
            key             TEXT               NOT NULL UNIQUE,
            iv              TEXT               NOT NULL UNIQUE);'''

userDbSQL = '''CREATE TABLE IF NOT EXISTS uname(
                id          INTEGER     PRIMARY KEY AUTOINCREMENT,
                website     text            NOT NULL,
                mail        VARCHAR(80)             ,
                username    VARCHAR(20)             ,
                password    VARCHAR(30)    NOT NULL);'''

insertUser2Master = "INSERT INTO master(username, password, recoverycode, key, iv) VALUES(?, ?, ?, ?, ?);"
queryUsernameRecovcode = "select * from master where username = ? and recoverycode = ?;"
updatePassword = "update master set password = ? where username = ? and recoverycode = ?;"
fetchInfoFromMaster = "select * from master where username = ? and password = ?;"

# * USER TABLE SQL STATEMENTS

insertInfo2User = "INSERT INTO uname(website, mail, username, password) VALUES(?, ?, ?, ?);"
searchWebsite = "select * from uname where website = ?;"
# ---
# * Check for the Platform

if sys.platform == "linux" or sys.platform == "linux2":
    
    # linux

    clearCMD = 'clear'
    dirName = 'KeyGaurd'
    desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    databaseDir = "~/.local/{dirName}"
    DBfile = f"{databaseDir}/password.kgdb"
    keyFile = f"{databaseDir}/EDKey.kgk"
    userDBFile = f'{databaseDir}/uname.kgdb'

    if not os.path.isdir(databaseDir):
        os.mkdir(databaseDir)
        open(DBfile, 'w+')
        conn = sqlite3.connect(DBfile)
        conn.execute(masterDbSQL)
        conn.commit()
        conn.close()  

elif sys.platform == "win32":

    # * Windows

    clearCMD = 'cls'
    dirName = 'KeyGuard'
    localAppData = os.path.expandvars(r'%LOCALAPPDATA%')
    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    databaseDir = f"{localAppData}/{dirName}"
    DBfile = f"{databaseDir}/password.kgdb"
    keyFile = f"{databaseDir}/EDKey.kgk"
    userDBFile = f'{databaseDir}/uname.kgdb'

     


def draw():

    # Fucntion to draw logo
    
    os.system(clearCMD)
    print(logo)

    return None


def random_recovery_word():

    # Generates random 10 words used to for changing password 
    words = []
    for _ in range(10):
        words.append(random.choice(recWordList))
    
    return " ".join(words)


def encryption(file, akey, iv):

    # AES Encryption Function
    with open(file, 'rb') as f:
        data = f.read()
        f.close()

    cipher = AES.new(akey, AES.MODE_CBC, iv)
    data = pad(data, AES.block_size)    

    cipherText = cipher.encrypt(data)
    
    with open(file, 'wb') as f:
        f.write(cipherText)
        f.close()


def decryption(file, akey, iv):
    
    # AES CBC Decryption Function, 
    with open(file, 'rb') as f:
        data = f.read()
        f.close()
    
    cipher = AES.new(akey, AES.MODE_CBC, iv)
    plainText = cipher.decrypt(data) 

    plainText = unpad(plainText, AES.block_size)
    
    with open(file, 'wb') as f:
        f.write(plainText)
        f.close()


def genrate_encryption_key():
    
    # Generates AES Keys for Users and Unique key for Encrypting Files
  
    key = Random.get_random_bytes(32)
    iv = Random.new().read(AES.block_size)
  
    return key, iv


def forgot_password():
    
    # Function to change Password

    draw()
    print("-"*60)
    print("| FORGOT PASSWORD")
    print("-"*60)
    
    # Inputs from User
    username = input("Username: ")
    recovCode = input("Recovery-Code: ").strip()
    
    # Decrypting Files
    decryption(DBfile, masterKey, masterIV)
    
    # Connecting to Database
    conn = sqlite3.connect(DBfile)   
    cur = conn.cursor()
    cur.execute(queryUsernameRecovcode, (username, recovCode))
    data = cur.fetchall()
    
    # Checking for correct username and recovery code
    if len(data) == 0:
        
        print('-'*60)
        print(f'USERNAME OR RECOVERY-CODE SUBMITTED IS INVALID.')
        print('-'*60)
        conn.close()
       
        encryption(DBfile, masterKey, masterIV)
        return None
    
    # TODO: Planning for getpass() Library, to get input from user 
    # If correct takes new password from user 

    print('-'*60)
    newPassword = input("New Password: ")
    newPassword = md5(newPassword.encode()).hexdigest()
    cur.execute(updatePassword, (newPassword, username, recovCode))
    cur.execute(fetchInfoFromMaster, (username, newPassword))
    conn.commit()
    data = cur.fetchall()
    conn.close()    
    
    # Encrypting Files
    encryption(DBfile, masterKey, masterIV)

    print('-'*60)
    print('PASSWORD CHANGED SUCCESSFUL')
    print('-'*60)   

    return None


def view_data(uname, ukey, iv):

    draw()
    print('-'*60)
    print(f"| VIEW {uname}'s DATA")
    print('-'*60)
    print('1. View All Data \n2. View Single Data\n\nx. Exit')
    
    # Input Validation

    while True:
        print('-'*60)
        choice = input("Choose [ 1 / 2 / x ] >> ")
        try:
            assert choice in dList         
        except AssertionError:
            print("Invalid Choice")     
        else:
            break

    # Conditional Execution

    if choice == '1':
        
        decryption(userDBFile.replace('uname', uname), ukey, iv)
        
        uConn = sqlite3.connect(userDBFile.replace('uname', uname))
        uCur = uConn.cursor()
        uCur.execute(f'''select * from {uname};''')
        data = uCur.fetchall()

        if len(data) == 0:

            print('-'*60)
            print("Data is unavailable because it is either empty or not saved.")
            print('-'*60)
            uConn.close()

            encryption(userDBFile.replace('uname', uname), ukey, iv)

            return None

        uConn.close()
        
        encryption(userDBFile.replace('uname', uname), ukey, iv)
        
        os.system(clearCMD)

        print('-'*60)
        print(f"| {uname}'s Stored Data:")
        print('-'*60)
        print()
        
        print(tabulate(data, headers=['Website', 'Mail-ID', 'Username', 'Password'], tablefmt='grid'))

    elif choice == '2':

        print('-'*60)
        websiteName = input("Search by website name: ").lower()

        decryption(userDBFile.replace('uname', uname), ukey, iv)

        uConn = sqlite3.connect(userDBFile.replace('uname', uname))
        uCur = uConn.cursor()
        uCur.execute(searchWebsite.replace("uname", uname), [websiteName])
        data = uCur.fetchall()

        if len(data) == 0:
    
            print('-'*60)
            print("Data is unavailable because it is either empty or not saved.")
            print('-'*60)
            uConn.close()

            encryption(userDBFile.replace('uname', uname), ukey, iv)

            return None
        
        uConn.close()
        
        encryption(userDBFile.replace('uname', uname), ukey, iv)
        
        os.system(clearCMD)
        
        print('-'*60)
        print(f"| {uname}'s {websiteName} Data:")       
        print('-'*60)
        print()
        print(tabulate(data, headers=['Website', 'Mail-ID', 'Username', 'Password'], tablefmt='grid'))
    
    else:
        return None

    print()
    print('-'*60)
    print(f"VIEWED {uname}'s DATA SUCCESSFUL")
    print('-'*60)

    return None    


def add_info(uname, ukey, iv):
    
    infoData = []
    
    draw()
    print('-'*60)
    print(f"| {uname} >> ADD DATA")

    # Input validation limits user for max of 10

    while True:
        print('-'*60)
        try:
            nData = int(input('Number of Info to be stored [1-10]: '))
            assert 0 < nData < 10
        except ValueError:
            print("Not an integer! Please enter an integer.")
        except AssertionError:
            print("Please enter an integer between 1 and 10")
        else:
            break
    
    # Stores the data in List variable called infoData
     
    for _ in range(nData):     
        print('-'*60)
        websiteName = input('Website Name: ').lower().strip()
        mailID = input('Mail ID: ')
        websiteUsername = input('Username: ')
        websitePassword = input('Password: ').strip()
        if (not websiteName or not websitePassword):
            print('-'*60)
            input("NOTE: Due to an empty mandatory field, the information you provided above was not stored.")
        else:
            infoData.append((websiteName, mailID, websiteUsername, websitePassword))
    
    # If information provided is 0, exits this function
    # If not continues to execute the below code
    
    if len(infoData) != 0:

        decryption(userDBFile.replace('uname', uname), ukey, iv)

        uConn = sqlite3.connect(userDBFile.replace('uname', uname))
        uCur = uConn.cursor()
    
        for i in infoData:
            uCur.execute(insertInfo2User.replace('uname', uname), (i[0], i[1], i[2], i[3]))


        uConn.commit()
        uConn.close()
        
        encryption(userDBFile.replace('uname', uname), ukey, iv)
    

    print('-'*60)
    print(f'DATA ADDED SUCCESSFUL')
    print('-'*60)
    
    return None


def existing_user():

    draw()
    print("-"*60) 
    print("| Welcome Existing User")
    print("-"*60) 
    
    uname = input("UserName >> ")
    passwd = input("Password >> ")
    passwd = md5(passwd.encode()).hexdigest()
    
    # Decrypts File
    
    decryption(DBfile, masterKey, masterIV)
    
    # Connects to Database and Fetches data

    conn = sqlite3.connect(DBfile)   
    cur = conn.cursor()
    cur.execute(fetchInfoFromMaster, (uname, passwd))
    data = cur.fetchone()
    conn.close() 

    # Encrypts File
    
    encryption(DBfile, masterKey, masterIV)

    # If length of data is 0 then wrong Credentials comes out of this function
    
    if data == None:
        print("-"*60) 
        print("INVALID CREDENTIALS.")
        print("-"*60) 
        
        return None

    # Fetches Unique key for User database and stores in variable
    key = data[4]
    iv = data[5]
    
    # if Correct credential, executes below code

    draw()
    print("-"*60) 
    print(f"| Welcome {uname}")
    print("-"*60) 
    print("1. Add Data \n2. View Data \n\nx. Exit")

    # Input Validation

    while True:
        print('-'*60)
        choice = input("Choose [ 1 / 2 / x ] >> ")
        try:
            assert choice in dList         
        except AssertionError:
            print("Invalid Choice")     
        else:
            break
    
    # Conditional execution
    
    if choice == "1":
        add_info(uname, key, iv)
    elif choice == "2":
        view_data(uname, key,iv)
    else:
        return None

    return None


def new_user():
    
    # Draws Logo
    
    draw()

    # Takes Input From User

    print("-"*60)
    print("| Welcome New User")
    while True: 
        print("-"*60)  
        uname = input("Username >> ")
        if uname.isalpha():
            break
        else:
            print("-"*60)  
            print("Username invalid. Usernames may only contain letters;\nnumbers and symbols are not permitted. To try once again, press the Enter key")
    
    # Password is Hashed and Key is generated for Encryption

    passwd = input("Password >> ")
    passwd = md5(passwd.encode()).hexdigest()
    recovCode = random_recovery_word()
    key, iv = genrate_encryption_key()
    key = key   
    iv = iv   
    
    # Decrypting Files

    decryption(DBfile, masterKey,masterIV)

    # On Valid Information Stores to Master Database and encrypts file 

    conn = sqlite3.connect(DBfile)   
    cur = conn.cursor()

    try:       
        cur.execute(insertUser2Master, (uname, passwd, recovCode, key, iv))
        conn.commit()
        open(userDBFile.replace('uname', uname), 'w+')
        nConn = sqlite3.connect(userDBFile.replace('uname', uname))
        nConn.execute(userDbSQL.replace('uname', uname))
        nConn.commit()
        nConn.close()

        encryption(userDBFile.replace('uname', uname), key, iv)

    # On Invalid Information Encrypts File and Exits out of script

    except Error:
        print('-'*60)
        print("NOTE: Please try again. User Already Exists.")
        print('-'*60)

        encryption(DBfile, masterKey, masterIV)
        
        return None

    conn.close()
    
    #  Encrypting Files

    encryption(DBfile, masterKey, masterIV)

    # Writes Username and Recover Code to File

    fileMsg = f'''{logo}
{'-'*80}
| Username And Recovery Code
{'-'*80}
| NOTE: KEEP THIS FILE SAFE
{'-'*80}
| Username: {uname}
| Recovery Code: {recovCode}
{'-'*80}'''

    with open(f'{desktop}/{uname}.txt', 'w+') as f:
        f.write(fileMsg)
        f.close()

    # Verbose Information  

    print('-'*60)
    print(f"Recovery Code: {recovCode}")
    print('-'*60)
    print(f'NEW USER: "{uname}" CREATED SUCCESSFUL')   
    print('-'*60)     
    print("Note: A File has been created which has Username and Recovery Code .\n     In case if you forget your master password, a recovery-code and\n     username will assist you in retrieve it. ")
    print('-'*60)
    print(f"File Location: {desktop}/{uname}.txt")
    print('-'*60)

    return None


def backup_files():

    # Copying File and Moving file from Devices

    draw()
    print("-"*60)
    print("| BACKUP/MOVE VAULT")
    print("-"*60)
    print("1. Copy VAULT from this device \n2. Move VAULT to this device\n\nx. Exit ")

    while True:
        print('-'*60)
        choice = input("Choose [ 1 / 2 / x ] >> ")
        try:
            assert choice in dList         
        except AssertionError:
            print("Invalid Choice")     
        else:
            break

    if choice == '1':
        
        if os.path.isdir(f'{desktop}/{dirName}'):
            shutil.rmtree(f'{desktop}/{dirName}')
        
        shutil.copytree(databaseDir, f'{desktop}/{dirName}')

        print('-'*60)
        print(f'VAULT is Copied to DESKTOP: "{desktop}"')
        print('-'*60)
        print('COPY SUCCESSFUL.')
        print('-'*60)

    elif choice == '2':

        if os.path.isdir(f'{desktop}/{dirName}'):

            shutil.rmtree(f'{localAppData}/{dirName}')
            shutil.copytree(f'{desktop}/{dirName}', f'{localAppData}/{dirName}')
            shutil.rmtree(f'{desktop}/{dirName}')
            print('-'*60)
            print('MOVED SUCCESSFUL')
            print('-'*60)
            input('Press Enter key to exit..')
            sys.exit()
        
        else:
            print('-'*60)
            print(f"VAULT NOT FOUND. Please Place VAULT in DESKTOP")
            print('-'*60)
            print('OPERATION UNSUCESSFUL')
            print('-'*60)

            return None

    else:
        return None

    return None


def main():
    
    # TODO: Encryption Related Stuff

    # Generates new key for encryption if not present 
    # If key present it decrypts files and reads key

    if not os.path.isdir(databaseDir):
        os.mkdir(databaseDir)
        open(DBfile, 'w+')
        conn = sqlite3.connect(DBfile)
        conn.execute(masterDbSQL)
        conn.commit()
        conn.close()
        encryption(DBfile,masterKey, masterIV) 
    
    # Main Functions starts from here
    # Loop for keeping main function running 

    while True:

        draw()

        print('-'*60)
        print(f"| Welcome {os.getlogin()}")
        print('-'*60)
        print(f"1. New User \n2. Existing User \n3. Forgot Password \n4. Backup/Move \n\nx. Exit")
        
        while True:
            print('-'*60)
            choice = input("Choose [ 1 / 2 / 3 / 4 / x ] >> ")
            try:
                assert choice in uList         
            except AssertionError:
                print("Invalid Choice")     
            else:
                break

        
        if choice == '1':
            new_user()
            print('-'*60)
            input('Press Enter key to continue..')

        elif choice == '2':
            existing_user()
            print('-'*60)
            input('Press Enter key to continue..')
        
        elif choice == '3':
            forgot_password()
            print('-'*60)
            input('Press Enter key to continue..')
        
        elif choice == '4':
            backup_files()
            print('-'*60)
            input('Press Enter key to continue..')

        else:
            break    
            
            
if __name__ == '__main__':
    main()          
