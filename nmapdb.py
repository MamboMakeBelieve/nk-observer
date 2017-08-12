#!/usr/bin/env python
#
# nmapdb - Parse nmap's XML output files and insert them into an SQLite database
# Original nmapdb.py by Patroklos Argyroudis <argp at domain census-labs.com>
# Updated/rewritten by Phil Young aka Soldier of FORTRAN
#        - Completly re-wrote script:
#            - Added support for updating entries in the database
#            - Added host script support
#            - Added script output appending (script output will not overwrite previous output)
#            - Removed booleans, replaced with python built-in

import sys
import os
import argparse
from pysqlite2 import dbapi2 as sqlite
from libnmap.parser import NmapParser

class c:
    BLUE = '\033[94m'
    DARKBLUE = '\033[0;34m'
    PURPLE = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[1;37m'
    ENDC = '\033[0m'
    DARKGREY = '\033[1;30m'


    def disable(self):
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.DARKBLUE = ''
        self.PURPLE = ''
        self.WHITE= ''
        self.RED = ''
        self.ENDC = ''

verbose = False

def debug(area ='',msg=''):
    global verbose
    if verbose:
        print '%s[+]%s %s %s>> %s%s%s' % (c.WHITE,c.GREEN,area,c.WHITE,c.YELLOW,msg,c.ENDC)
    return

def mesg(area ='',msg=''):
    print '%s[+]%s %s %s>> %s%s%s' % (c.WHITE,c.GREEN,area,c.WHITE,c.YELLOW,msg,c.ENDC)
    return

def err(area ='',msg=''):
    print '%s[!]%s %s %s>> %s%s%s' % (c.RED,c.RED,area,c.RED,c.RED,msg,c.ENDC)
    return

def sql_struct():
    return '''CREATE TABLE IF NOT EXISTS hosts (
    ip          VARCHAR(16) PRIMARY KEY NOT NULL,
    mac         VARCHAR(18),
    hostname    VARCHAR(129),
    protocol    VARCHAR(5) DEFAULT 'ipv4',
    os_name     TEXT,
    os_family   TEXT,
    os_accuracy INTEGER,
    os_gen      TEXT,
    last_update TIMESTAMP,
    state       VARCHAR(8) DEFAULT 'down',
    mac_vendor  TEXT,
    info        TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    ip          VARCHAR(16) NOT NULL,
    port        INTEGER NOT NULL,
    protocol    VARCHAR(4) NOT NULL,
    name        VARCHAR(33),
    state       VARCHAR(33) DEFAULT 'closed',
    service     TEXT,
    info        TEXT,
    PRIMARY KEY (ip, port, protocol),
    CONSTRAINT fk_ports_hosts FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS fki_ports_hosts_ip
BEFORE INSERT ON ports
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'insert on table "ports" violates foreign key constraint "fk_ports_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fku_ports_hosts_ip
BEFORE UPDATE ON ports
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'update on table "ports" violates foreign key constraint "fk_ports_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fkd_ports_hosts_ip
BEFORE DELETE ON hosts
FOR EACH ROW BEGIN
    DELETE from ports WHERE ip = OLD.ip;
END;'''

def dict_factory(cursor, row):
    d = {}
    for idx,col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def main(argv, environ):
    global verbose
    #start argument parser
    parser = argparse.ArgumentParser(description='Nmap XML file to SQLite database. Default file nmap.db will be used if none is supplied.')
    parser.add_argument('--debug',help='Print verbose information',default=False,dest='debug',action='store_true')
    parser.add_argument('--force-update',help='Overwrite previous information.',default=False,dest='force',action='store_true')    
    parser.add_argument('-d','--database',help='Filename to use for database. If file doesn\'t exist it will be created. Default is \'nmap.db.\'',dest='scandb', default='nmap.db')
    parser.add_argument('nmap_xml',help='Nmap XML file you wish to parse')
    args = parser.parse_args()

    if args.debug:
        verbose = True
        debug('Start ','Debug Enabled')

    mesg('Start ','Using DB file: %s and XML file %s' % (args.scandb,args.nmap_xml))  
    conn = sqlite.connect(args.scandb)
    cursor = conn.cursor()
    debug("Start ","Successfully connected to SQLite DB \"%s\"" % (args.scandb))
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    if (u'hosts',) not in cursor.fetchall():
        debug('Start ', 'Database does not exist. Creating...Done') 
        try:
            cursor.executescript(sql_struct())
        except sqlite.ProgrammingError, msg:
            err("Start ","%s: error: %s\n" % (argv[0], msg))
            sys.exit(1)
    else:
        debug('Start ', 'Database already exists. Continuing.') 

    try:
        nmap_report = NmapParser.parse_fromfile(args.nmap_xml)
        debug("Parser","Nmap Results: {0}".format(nmap_report.summary))
    except IOError:
        err("Parser"," %s: error: file \"%s\" doesn't exist" % (argv[0], args.nmap_xml))
        sys.exit(-1)
    except:
        err("Parser"," %s: error: file \"%s\" Issue parsing Nmap XML" % (argv[0], args.nmap_xml))
        sys.exit(-1)

    for host in nmap_report.hosts:
        ip           = host.address
        mac          = host.mac
        if not host.ipv6:
            protocol = 'ipv4'
        else:
            protocol = 'ipv6'
        
        if len(host.hostnames) > 0:  #I know this isn't great but its fine for now
            hostname = host.hostnames[0]
        else:
            hostname = ''
        if host.os_fingerprinted:
            os_name     = host.os.osmatches[0].name
            os_family   = host.os.osmatches[0].osclasses[0].osfamily
            os_accuracy = host.os.osmatches[0].accuracy
            os_gen      = host.os.osmatches[0].osclasses[0].osgen
        else:
            os_name     = ''
            os_family   = ''
            os_accuracy = ''
            os_gen      = ''

        timestamp   = host.endtime
        state       = host.status
        mac_vendor  = host.vendor
        
        # Some script store results in host scripts, we'll store them in one long string
        host_script = ""
        for script_out in host.scripts_results:
            debug("[host]","Found script output for %s" % script_out['id'])
            host_script += script_out['id']+":\n"+script_out['output']+'\n'
            if len(script_out['elements']) > 0: host_script +=  '  Elements:\n'
            for elem in script_out['elements']:
                if type(script_out['elements'][elem]) is not dict:
                    host_script += '    '+str(elem)+": "+ str(script_out['elements'][elem])+'\n'
                else:
                    host_script += '    '+elem+':\n'
                    for item in script_out['elements'][elem]:
                        if item is not None and script_out['elements'][elem][item] is not None: 
                            host_script += '      '+item+': '+script_out['elements'][elem][item].strip()+'\n'
            host_script += '\n'

        info_str = ''   
        for line in host_script.splitlines():
            info_str += '['+ip+'] '+line+'\n'

        
        debug("[host]","ip:          %s" % (ip))
        debug("[host]","mac:         %s" % (mac))
        debug("[host]","hostname:    %s" % (hostname))
        debug("[host]","protocol:    %s" % (protocol))
        debug("[host]","os_name:     %s" % (os_name))
        debug("[host]","os_family:   %s" % (os_family))
        debug("[host]","os_accuracy: %s" % (os_accuracy))
        debug("[host]","os_gen:      %s" % (os_gen))
        debug("[host]","last_update: %s" % (timestamp))
        debug("[host]","state:       %s" % (state))
        debug("[host]","mac_vendor:  %s" % (mac_vendor))
        debug("[host]","info:        %s" % info_str)
        debug("[host]","Inserting %s in to database" % ip)
        try:
            cursor.execute("INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ip, mac, hostname, protocol, os_name, os_family, os_accuracy,
                    os_gen, timestamp, state, mac_vendor, info_str))
            debug("[host]","Inserted  %s in to database" % ip)

        except sqlite.IntegrityError, msg:

            debug("[host]","Entry alread exists for %s in database attempting update" % ip)
            cursor.execute("SELECT * FROM hosts WHERE ip = '%s'" % ip )
            db = dict_factory(cursor, cursor.fetchone())
            
            # We automatically append new script output without asking the user
            if host_script != "" and db['info'].find(info_str) < 0:
                new_info = db['info'] + "\n" + info_str
                debug("[host]"," Appending script output")
                cursor.execute("UPDATE hosts SET info=? WHERE ip = ?" , (new_info, ip))

            if args.force:
                    debug("[host]","--force-update enabled - overwritting entry!")
                    cursor.execute("UPDATE hosts SET mac=?, hostname=?, protocol=?, os_name=?, os_family=?, os_accuracy=?, os_gen=?, last_update=?, state=?, mac_vendor=?, info=? WHERE ip = ?", (mac,hostname,protocol,os_name,os_family,os_accuracy,os_gen,timestamp,state,mac_vendor,host_script, ip ))


            # If the host already exsits lets check with the user if we wan't to update
            if (    db['mac']       != mac 
                and db['hostname']  != hostname  and db['hostname'] != ''
                and db['protocol']  != protocol 
                and db['os_name']   != os_name   and db['os_name'] != ''
                and db['os_family'] != os_family and db['os_family'] != ''
                and db['os_gen']    != os_gen    and db['os_gen'] != ''
                and db['state']     != state 
                and db['mac_vendor']!= mac_vendor 
                and db['info']      != host_script) and not args.force:
                # So we already have an entry. If theres no new information we continue to ports
                # If there's a bunch of new entries we'll ask the user what to do
                debug("[host]","Could not update automatically - Manual update required")
                mesg("[host]","%s entry exists" % ip)
                mesg("[host]","Name:        'Old' --> 'New'")
                mesg("[host]","mac:         '"+db['mac']+"' --> '%s'" % mac)
                mesg("[host]","hostname:    '"+db['hostname']+"' --> '%s'" % hostname)
                mesg("[host]","protocol:    '"+db['protocol']+"' --> '%s'" % protocol)
                mesg("[host]","os_name:     '"+db['os_name']+"' --> '%s'" % os_name)
                mesg("[host]","os_family:   '"+db['os_family']+"' --> '%s'" % os_family)
                mesg("[host]","os_accuracy: '"+str(db['os_accuracy'])+"' --> '%s'" % os_accuracy)
                mesg("[host]","os_gen:      '"+db['os_gen']+"' --> '%s'" % os_gen)
                mesg("[host]","timestamp:   '"+str(db['last_update'])+"' --> '%s'" % timestamp)
                mesg("[host]","state:       '"+db['state']+"' --> '%s'" % state)
                mesg("[host]","mac_vendor:  '"+db['mac_vendor']+" --> '%s'" % mac_vendor)
                mesg("[host]","info:        '"+db['info']+"' --> '%s'" % host_script)
                mesg("[host]","Update entry? y/n")
                user_input = sys.stdin.readline().strip()[:1]
                if user_input == 'y':
                    debug("[host]","Updating %s entry" % ip)
                    cursor.execute("UPDATE hosts SET mac=?, hostname=?, protocol=?, os_name=?, os_family=?, os_accuracy=?, os_gen=?, last_update=?, state=?, mac_vendor=?, info=? WHERE ip = ?", (mac,hostname,protocol,os_name,os_family,os_accuracy,os_gen,timestamp,state,mac_vendor,host_script, ip ))
                else:
                    debug("[hosts]","Skipping %s entry" % ip)
        except:
            print "%s: unknown exception during insert into table hosts\n" % (argv[0])
            continue

        ports = host.get_open_ports()
        
        for port in ports:
            svc = host.get_service(port[0])
            service_str = svc.banner
            port_name = svc.service
            pn = str(svc.port)
            protocol = svc.protocol
            state = svc.state

            # Service Scripts - we'll store them in one long string
            svc_script = ""
            for script_out in svc.scripts_results:
                debug("[port]","Found script output for %s" % script_out['id'])
                svc_script += script_out['id']+":\n"+script_out['output']+'\n'
                if len(script_out['elements']) > 0: svc_script +=  '  Elements:\n'
                for elem in script_out['elements']:
                    if not elem:
                        continue
                    if (type(script_out['elements'][elem]) is not dict  
                    and type(script_out['elements'][elem]) is not list):
                        svc_script += '    '+str(elem)+": "+ script_out['elements'][elem]+'\n'
                    elif type(script_out['elements'][elem]) is dict:
                        svc_script += '    '+elem+':\n'
                        for item in script_out['elements'][elem]:
                            if item is not None and script_out['elements'][elem][item] is not None: 
                                svc_script += '      '+item+': '+script_out['elements'][elem][item].strip()+'\n'

                svc_script += '\n'
                #print svc_script
            info_str = ''
            for line in svc_script.splitlines():
                info_str += "[%s:%s] %s\n" % (ip, pn, line)
            
            debug("[port]","---------------------- Start  "+pn+"    ----------------------")
            debug("[port]","ip:       %s" % (ip))
            debug("[port]","port:     %s" % (pn))
            debug("[port]","protocol: %s" % (protocol))
            debug("[port]","name:     %s" % (port_name))
            debug("[port]","state:    %s" % (state))
            debug("[port]","service:  %s" % (service_str))
            debug("[port]","info:     %s" % (info_str))
            debug("[host]","Attempting to insert %s:%s in to database" % (ip,pn))

            try:
                cursor.execute("INSERT INTO ports VALUES (?, ?, ?, ?, ?, ?, ?)", (ip, pn, protocol, port_name, state, service_str, info_str))
            except sqlite.IntegrityError, msg:
                debug("[port]","Entry alread exists for %s:%s in database attempting update" % (ip,pn))

                cursor.execute("SELECT * FROM ports WHERE ip = '%s' AND port = '%s' and protocol ='%s'" % (ip, pn, protocol) )
                db = dict_factory(cursor, cursor.fetchone())

                # We automatically append new script output without asking the user
                if info_str != "" and db['info'].find(info_str) < 0:
                    new_info = db['info'] + "\n" + info_str
                    debug("[port]","Appending script output %s" % info_str)
                    cursor.execute("UPDATE ports SET info=? WHERE ip = ? AND port = ? and protocol =?" , (new_info, ip, pn, protocol))
                    
                if args.force:
                    debug("[port]","--force-update enabled - overwritting entry!")
                    cursor.execute("UPDATE ports SET name=?, state=?, service=? WHERE ip = ? AND port = ? and protocol = ?",
                           (port_name, state, service_str, ip, pn, protocol))

                if (not args.force) and (db['name'] != port_name or db['service'] != service_str or db['state'] != state) and service_str != '':
                    debug("[port]","Could not update automatically - Manual update required")
                    err("[!!!!]","------------------- MANUAL UPDATE REQUIRED! -----------------------")
                    mesg("[port]","%s:%s %s exists" % (ip, pn, protocol))
                    mesg("[port]","Name:     'Old' --> 'New'")
                    mesg("[port]","ip:       '"+db['ip']+"' --> '%s'" % ip)
                    mesg("[port]","port:     '"+str(db['port'])+"' --> '%s'" % pn)
                    mesg("[port]","protocol: '"+db['protocol']+"' --> '%s'" % protocol)
                    mesg("[port]","name:     '"+db['name']+"' --> '%s'" % port_name)
                    mesg("[port]","state:    '"+db['state']+"' --> '%s'" % state)
                    mesg("[port]","service:  '"+db['service']+"' --> '%s'" % service_str)
                    mesg("[port]","Update entry? y/n")
                    user_input = sys.stdin.readline().strip()[:1]
                    if user_input == 'y':
                        cursor.execute("UPDATE ports SET name=?, state=?, service=? WHERE ip = ? AND port = ? and protocol = ?",
                           (port_name, state, service_str, ip, pn, protocol))
                    else: debug('[port]',' skipping entry')

            except:
                print "%s: unknown exception during insert into table ports\n" % (argv[0])
                continue
            debug("[port]","---------------------- End    "+pn+"    ----------------------")


        debug("[host]",    "====================== End "+ip+" ======================")


    conn.commit()

if __name__ == "__main__":
    main(sys.argv, os.environ)
    sys.exit(0)

