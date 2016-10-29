import re
import sys
import os
import contextlib
import tempfile
import shutil
import hashlib
import string
from datetime import datetime

# ATENTION!!!
# you must enter the absolute path of the dump
path_dumps = '/media/cec/0E8C0B788C0B5A1B/TFG/VolGUI/VolGUI_V0.4.1_ACABADO/VolGUI/web/dumps/'

import logging
logger = logging.getLogger(__name__)

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

try:
    from bson.objectid import ObjectId
except ImportError:
    logger.error('Unable to import pymongo')
    sys.exit()

from django.shortcuts import render, redirect

from django.http import HttpResponse, HttpResponseServerError

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt

try:
    from virus_total_apis import PublicApi
    VT_LIB = True
except ImportError:
    VT_LIB = False
    logger.error("Unable to import API Library")

try:
    import yara
    YARA = True
except ImportError:
    YARA = False
    logger.error("Unable to import Yara")

try:
    from vt_key import API_KEY
    VT_KEY = True
except ImportError:
    VT_KEY = False
    logger.error("Unable to import API Key from vt_key.py")

##
# Import The volatility Interface and DB Class
##
import vol_interface
from vol_interface import RunVol

try:
    from web.database import Database
    db = Database()
except Exception as e:
    logger.error("Unable to access mongo database: {0}".format(e))


##
# Helpers
##

volutility_version = '0.1'

volrc_file = os.path.join(os.path.expanduser('~'), '.volatilityrc')


def string_clean_hex(line):
    line = str(line)
    new_line = ''
    for c in line:
        if c in string.printable:
            new_line += c
        else:
            new_line += '\\x' + c.encode('hex')
    return new_line


def hex_dump(hex_cmd):
    hex_string = getoutput(hex_cmd)

    # Format the data
    html_string = ''
    hex_rows = hex_string.split('\n')
    for row in hex_rows:
        if len(row) > 9:
            off_str = row[0:8]
            hex_str = row[9:58]
            asc_str = row[58:78]
            asc_str = asc_str.replace('"', '&quot;')
            asc_str = asc_str.replace('<', '&lt;')
            asc_str = asc_str.replace('>', '&gt;')
            html_string += '<div class="row"><span class="text-info mono">{0}</span> <span class="text-primary mono">{1}</span> <span class="text-success mono">{2}</span></div>'.format(off_str, hex_str, asc_str)
    # return the data
    return html_string

def getPluginBysessionIdAndName(session_id, plugin_name):
    	plugin_name = db.get_pluginby_session_and_name(session_id, plugin_name)
    	return plugin_name

# context manager for dump-dir
@contextlib.contextmanager
def temp_dumpdir():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)




##
# Page Views
##
#
def index(request):
    name_view = "index"
    return render(request, 'index.html',{'name_view': name_view})

# LIST SESSIONS PAGE
def list_sessions(request, error_line=False):
    name_view = "list_sessions"
    
    # Check Vol Version
    if float(vol_interface.vol_version) < 2.5:
        error_line = 'UNSUPPORTED VOLATILITY VERSION. REQUIRES 2.5 FOUND {0}'.format(vol_interface.vol_version)

    # Set Pagination
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 30

    # Get All Sessions
    session_list = db.get_allsessions()

    # Paginate
    session_count = len(session_list)
    first_session = int(page) * int(page_count) - int(page_count) + 1
    last_session = int(page) * int(page_count)

    paginator = Paginator(session_list, page_count)

    try:
        sessions = paginator.page(page)
    except PageNotAnInteger:
        sessions = paginator.page(1)
    except EmptyPage:
        sessions = paginator.page(paginator.num_pages)

    # Show any extra loaded plugins
    plugin_dirs = []
    if os.path.exists(volrc_file):
        vol_conf = open(volrc_file, 'r').readlines()
        for line in vol_conf:
            if line.startswith('PLUGINS'):
                plugin_dirs = line.split(' = ')[-1]

    # Profile_list for add session
    RunVol('', '')
    profile_list = vol_interface.profile_list()

    return render(request, 'list_sessions.html', {'name_view': name_view,
                                          'session_list': sessions,
                                          'session_counts': [session_count, first_session, last_session],
                                          'profile_list': profile_list,
                                          'plugin_dirs': plugin_dirs,
                                          'error_line': error_line
                                          })

# SESSION PAGE
def session_page(request, sess_id):
    # Profile_list for add session
    RunVol('', '')
    profile_list = vol_interface.profile_list()
    #yara_list = os.listdir("/media/cec/0E8C0B788C0B5A1B/TFG/VolGUI/VolGUI_V0.3/VolGUI/yararules")
    
    name_view = "session_page"
    error_line = False

    # Check Vol Version
    if float(vol_interface.vol_version) < 2.5:
        error_line = 'UNSUPPORTED VOLATILITY VERSION. REQUIRES 2.5 FOUND {0}'.format(vol_interface.vol_version)

    # Get the session
    session_id = ObjectId(sess_id)
    session_details = db.get_session(session_id)
    
    profilesDic = session_details['image_info']
    profile_image = profilesDic['Suggested Profile(s)'].split(", ")[0]
    
    comments = db.get_commentbysession(session_id)
    plugin_list = []
    plugin_text = db.get_pluginbysession(ObjectId(sess_id))
    version_info = {'python': str(sys.version).split()[0],
                    'volatility': vol_interface.vol_version,
                    'volutility': volutility_version}
                    
    # WINDOWS CORE MENU
    # Image Identification
    plugin_imageinfo = db.get_pluginby_session_and_name(session_id, 'imageinfo')
    plugin_kdbgscan = db.get_pluginby_session_and_name(session_id, 'kdbgscan')
    plugin_kpcrscan = db.get_pluginby_session_and_name(session_id, 'kpcrscan')
    plugin_pslist = db.get_pluginby_session_and_name(session_id, 'pslist')
    # Processes and DLLs
    plugin_pstree = db.get_pluginby_session_and_name(session_id, 'pstree')
    plugin_psscan = db.get_pluginby_session_and_name(session_id, 'psscan')
    plugin_psdispscan = db.get_pluginby_session_and_name(session_id, 'psdispscan') #(this element is NOT in the DATABASE)
    plugin_dlllist = db.get_pluginby_session_and_name(session_id, 'dlllist')
    plugin_dlldump = db.get_pluginby_session_and_name(session_id, 'dlldump')
    plugin_handles = db.get_pluginby_session_and_name(session_id, 'handles')
    plugin_getsids = db.get_pluginby_session_and_name(session_id, 'getsids')
    plugin_cmdscan = db.get_pluginby_session_and_name(session_id, 'cmdscan')
    plugin_consoles = db.get_pluginby_session_and_name(session_id, 'consoles')
    plugin_privs = db.get_pluginby_session_and_name(session_id, 'privs')
    plugin_envars = db.get_pluginby_session_and_name(session_id, 'envars')
    plugin_verinfo = db.get_pluginby_session_and_name(session_id, 'verinfo')
    plugin_enumfunc = db.get_pluginby_session_and_name(session_id, 'enumfunc') #(this element is NOT in the DATABASE)
    # Process Memory
    plugin_memmap = db.get_pluginby_session_and_name(session_id, 'memmap')
    plugin_memdump = db.get_pluginby_session_and_name(session_id, 'memdump')
    plugin_procdump = db.get_pluginby_session_and_name(session_id, 'procdump')
    plugin_vadinfo = db.get_pluginby_session_and_name(session_id, 'vadinfo')
    plugin_vadwalk = db.get_pluginby_session_and_name(session_id, 'vadwalk')
    plugin_vadtree = db.get_pluginby_session_and_name(session_id, 'vadtree')
    plugin_vaddump = db.get_pluginby_session_and_name(session_id, 'vaddump')
    plugin_evtlogs = db.get_pluginby_session_and_name(session_id, 'evtlogs')
    plugin_iehistory = db.get_pluginby_session_and_name(session_id, 'iehistory')
    # Kernel Memory and Objects
    plugin_modules = db.get_pluginby_session_and_name(session_id, 'modules')
    plugin_modscan = db.get_pluginby_session_and_name(session_id, 'modscan')
    plugin_moddump = db.get_pluginby_session_and_name(session_id, 'moddump')
    plugin_ssdt = db.get_pluginby_session_and_name(session_id, 'ssdt')
    plugin_driverscant = db.get_pluginby_session_and_name(session_id, 'driverscant')#(this element is NOT in the DATABASE)
    plugin_filescan = db.get_pluginby_session_and_name(session_id, 'filescan')
    plugin_mutantscan = db.get_pluginby_session_and_name(session_id, 'mutantscan')
    plugin_symlinkscan = db.get_pluginby_session_and_name(session_id, 'symlinkscan')
    plugin_thrdscan = db.get_pluginby_session_and_name(session_id, 'thrdscan')
    plugin_dumpfiles = db.get_pluginby_session_and_name(session_id, 'dumpfiles')
    plugin_unloadedmodules = db.get_pluginby_session_and_name(session_id, 'unloadedmodules')
    # Networking
    plugin_connections = db.get_pluginby_session_and_name(session_id, 'connections')
    plugin_connscan = db.get_pluginby_session_and_name(session_id, 'connscan')
    plugin_sockets = db.get_pluginby_session_and_name(session_id, 'sockets')
    plugin_sockscan = db.get_pluginby_session_and_name(session_id, 'sockscan')
    plugin_netscan = db.get_pluginby_session_and_name(session_id, 'netscan')
    # Registry
    plugin_hivelist = db.get_pluginby_session_and_name(session_id, 'hivelist')
    plugin_printkey = db.get_pluginby_session_and_name(session_id, 'printkey')
    plugin_hivedump = db.get_pluginby_session_and_name(session_id, 'hivedump') #(this element is NOT in the DATABASE)
    plugin_hashdump = db.get_pluginby_session_and_name(session_id, 'hashdump')
    plugin_lsadump = db.get_pluginby_session_and_name(session_id, 'lsadump')
    plugin_userassist = db.get_pluginby_session_and_name(session_id, 'userassist')
    plugin_shellbags = db.get_pluginby_session_and_name(session_id, 'shellbags')
    plugin_shimcache = db.get_pluginby_session_and_name(session_id, 'shimcache')
    plugin_getservicesids = db.get_pluginby_session_and_name(session_id, 'getservicesids')
    plugin_dumpregistry = db.get_pluginby_session_and_name(session_id, 'dumpregistry')
    # Crash Dumps, Hibernation, and Conversion
    plugin_crashinfo = db.get_pluginby_session_and_name(session_id, 'crashinfo')#(this element is NOT in the DATABASE)
    plugin_hibinfo = db.get_pluginby_session_and_name(session_id, 'hibinfo')
    plugin_imagecopy = db.get_pluginby_session_and_name(session_id, 'imagecopy')
    plugin_raw2dmp = db.get_pluginby_session_and_name(session_id, 'raw2dmp')
    plugin_vboxinfo = db.get_pluginby_session_and_name(session_id, 'vboxinfo')
    plugin_vmwareinfo = db.get_pluginby_session_and_name(session_id, 'vmwareinfo')
    plugin_hpakinfo = db.get_pluginby_session_and_name(session_id, 'hpakinfo')
    plugin_hpakextract = db.get_pluginby_session_and_name(session_id, 'hpakextract')
    # File System
    plugin_mbrparser = db.get_pluginby_session_and_name(session_id, 'mbrparser')
    plugin_mftparser = db.get_pluginby_session_and_name(session_id, 'mftparser')
    # Miscellaneous
    plugin_strings = db.get_pluginby_session_and_name(session_id, 'strings')
    plugin_volshell = db.get_pluginby_session_and_name(session_id, 'volshell')
    plugin_bioskbd = db.get_pluginby_session_and_name(session_id, 'bioskbd')
    plugin_patcher = db.get_pluginby_session_and_name(session_id, 'patcher')
    plugin_pagecheck = db.get_pluginby_session_and_name(session_id, 'pagecheck')
    plugin_timeliner = db.get_pluginby_session_and_name(session_id, 'timeliner')
    
    # WINDOWS GUI MENU
    plugin_sessions = db.get_pluginby_session_and_name(session_id, 'sessions')
    plugin_wndscan = db.get_pluginby_session_and_name(session_id, 'wndscan')
    plugin_deskscan = db.get_pluginby_session_and_name(session_id, 'deskscan')
    plugin_atomscan = db.get_pluginby_session_and_name(session_id, 'atomscan')
    plugin_atoms = db.get_pluginby_session_and_name(session_id, 'atoms')
    plugin_clipboard = db.get_pluginby_session_and_name(session_id, 'clipboard')
    plugin_eventhooks = db.get_pluginby_session_and_name(session_id, 'eventhooks')
    plugin_gahti = db.get_pluginby_session_and_name(session_id, 'gahti')
    plugin_messagehooks = db.get_pluginby_session_and_name(session_id, 'messagehooks')
    plugin_userhandles = db.get_pluginby_session_and_name(session_id, 'userhandles')
    plugin_screenshot = db.get_pluginby_session_and_name(session_id, 'screenshot')
    plugin_gditimers = db.get_pluginby_session_and_name(session_id, 'gditimers')
    plugin_windows = db.get_pluginby_session_and_name(session_id, 'windows')
    plugin_wintree = db.get_pluginby_session_and_name(session_id, 'wintree')
    
    # WINDOWS MALWARE
    plugin_malfind = db.get_pluginby_session_and_name(session_id, 'malfind')
    plugin_svcscan = db.get_pluginby_session_and_name(session_id, 'svcscan')
    plugin_ldrmodules = db.get_pluginby_session_and_name(session_id, 'ldrmodules')
    plugin_impscan = db.get_pluginby_session_and_name(session_id, 'impscan')
    plugin_apihooks = db.get_pluginby_session_and_name(session_id, 'apihooks')
    plugin_gdt = db.get_pluginby_session_and_name(session_id, 'gdt')
    plugin_threads = db.get_pluginby_session_and_name(session_id, 'threads')
    plugin_callbacks = db.get_pluginby_session_and_name(session_id, 'callbacks')
    plugin_driverirp = db.get_pluginby_session_and_name(session_id, 'driverirp')
    plugin_devicetree = db.get_pluginby_session_and_name(session_id, 'devicetree')
    plugin_psxview = db.get_pluginby_session_and_name(session_id, 'psxview')
    plugin_timers = db.get_pluginby_session_and_name(session_id, 'timers')
    #Views
    plugin_objtypescan = db.get_pluginby_session_and_name(session_id, 'objtypescan')
    plugin_bigpools = db.get_pluginby_session_and_name(session_id, 'bigpools')
    plugin_auditpol = db.get_pluginby_session_and_name(session_id, 'auditpol')

    return render(request, 'session.html', {
	  # WINDOWS MALWARE
	  'plugin_malfind' : plugin_malfind, 'plugin_svcscan' : plugin_svcscan, 'plugin_ldrmodules': plugin_ldrmodules, 'plugin_impscan' : plugin_impscan, 'plugin_apihooks' : plugin_apihooks, 'plugin_gdt' : plugin_gdt, 'plugin_threads' : plugin_threads, 'plugin_callbacks' : plugin_callbacks,
	  'plugin_driverirp' : plugin_driverirp, 'plugin_devicetree' : plugin_devicetree,'plugin_psxview' : plugin_psxview, 'plugin_timers' : plugin_timers,
	  
      # WINDOWS GUI MENU
      'plugin_sessions' : plugin_sessions,'plugin_wndscan' : plugin_wndscan, 'plugin_deskscan' : plugin_deskscan,'plugin_atomscan' : plugin_atomscan,'plugin_atoms' : plugin_atoms, 'plugin_clipboard' : plugin_clipboard, 'plugin_eventhooks' : plugin_eventhooks,'plugin_gahti' : plugin_gahti,
      'plugin_messagehooks' : plugin_messagehooks,'plugin_userhandles' : plugin_userhandles,'plugin_screenshot' : plugin_screenshot,'plugin_gditimers' : plugin_gditimers, 'plugin_windows' : plugin_windows, 'plugin_wintree' : plugin_wintree,
      
      # WINDOWS CORE MENU
      # Miscellaneous
      'plugin_strings' : plugin_strings,'plugin_volshell': plugin_volshell,'plugin_bioskbd' : plugin_bioskbd,'plugin_patcher' : plugin_patcher,'plugin_pagecheck' : plugin_pagecheck,'plugin_timeliner' : plugin_timeliner,
      # File System
      'plugin_mftparser' : plugin_mftparser, 'plugin_mbrparser' : plugin_mbrparser,
      # Crash Dumps, Hibernation, and Conversion
      'plugin_hpakextract' : plugin_hpakextract,'plugin_hpakinfo' : plugin_hpakinfo,'plugin_vmwareinfo' : plugin_vmwareinfo,'plugin_vboxinfo' : plugin_vboxinfo,'plugin_raw2dmp' : plugin_raw2dmp,'plugin_imagecopy' : plugin_imagecopy,'plugin_hibinfo' : plugin_hibinfo,'plugin_crashinfo' : plugin_crashinfo,
      # Registry
      'plugin_dumpregistry' : plugin_dumpregistry,'plugin_getservicesids' : plugin_getservicesids,'plugin_shimcache' : plugin_shimcache,'plugin_shellbags' : plugin_shellbags, 'plugin_userassist' : plugin_userassist,'plugin_lsadump' : plugin_lsadump,'plugin_hashdump' : plugin_hashdump,'plugin_hivedump' : plugin_hivedump,'plugin_printkey' : plugin_printkey,'plugin_hivelist' :plugin_hivelist,
       # Networking
      'plugin_netscan' : plugin_netscan,'plugin_sockscan' : plugin_sockscan,'plugin_sockets' : plugin_sockets,'plugin_connscan' : plugin_connscan,'plugin_connections' : plugin_connections,
       # Kernel Memory and Objects
      'plugin_unloadedmodules' : plugin_unloadedmodules,'plugin_dumpfiles' : plugin_dumpfiles,'plugin_thrdscan' : plugin_thrdscan,'plugin_symlinkscan' : plugin_symlinkscan,'plugin_mutantscan' : plugin_mutantscan,'plugin_filescan' : plugin_filescan,'plugin_driverscant' : plugin_driverscant,'plugin_ssdt' : plugin_ssdt,'plugin_moddump' : plugin_moddump,'plugin_modscan' : plugin_modscan,'plugin_modules' : plugin_modules,
       # Process Memory
      'plugin_iehistory': plugin_iehistory,'plugin_evtlogs' : plugin_evtlogs,'plugin_vaddump': plugin_vaddump,'plugin_vadtree' : plugin_vadtree,'plugin_vadwalk': plugin_vadwalk,'plugin_vadinfo' :plugin_vadinfo,'plugin_procdump' : plugin_procdump,'plugin_memdump' : plugin_memdump,'plugin_memmap' : plugin_memmap,
       # Processes and DLLs
      'plugin_enumfunc' : plugin_enumfunc,'plugin_verinfo' : plugin_verinfo,'plugin_envars' : plugin_envars,'plugin_privs' : plugin_privs,'plugin_consoles' : plugin_consoles,'plugin_cmdscan' : plugin_cmdscan,'plugin_getsids' : plugin_getsids,'plugin_handles' : plugin_handles,'plugin_dlldump' : plugin_dlldump,'plugin_dlllist' : plugin_dlllist,'plugin_psdispscan' : plugin_psdispscan,'plugin_psscan' : plugin_psscan,'plugin_pstree' : plugin_pstree,'plugin_pslist' : plugin_pslist,
       # Image Identification
      'plugin_kpcrscan' : plugin_kpcrscan,'plugin_kdbgscan' : plugin_kdbgscan,'plugin_imageinfo': plugin_imageinfo,
      #Views
      'plugin_objtypescan' : plugin_objtypescan,
      'plugin_bigpools' : plugin_bigpools,
      'plugin_auditpol' : plugin_auditpol,
      
      'session_id': session_id,
      'profile_list': profile_list,
      'name_view': name_view,
      'session_details': session_details,
      'plugin_list': plugin_list,
      'plugin_output': plugin_text,
      'comments': comments,
      'error_line': error_line,
      'version_info': version_info,
      'profile_image': profile_image})


# Post Handlers
def create_session(request):
    # Get some vars
    new_session = {'created': datetime.now(), 'modified': datetime.now()}
    
    # Check the Input length
    if len(request.POST['sess_name']) == 0:
        logger.error('Please, enter a session name')
        return list_sessions(request, error_line='Please, enter a session name')

    if 'sess_name' in request.POST:
        new_session['session_name'] = request.POST['sess_name']

    dump_file = request.FILES['dump_name']
    path_file = path_dumps + dump_file.name
    with open(path_file, 'wb+') as destination:
         for chunk in dump_file.chunks():
           destination.write(chunk)
    destination.close()
    new_session['session_path'] = path_file
    
    if 'description' in request.POST:
        new_session['session_description'] = request.POST['description']
    if 'plugin_path' in request.POST:
        new_session['plugin_path'] = request.POST['plugin_path']

    # Check for mem file
    if not os.path.exists(new_session['session_path']):
        logger.error('Unable to find an image file at {0}'.format(request.POST['sess_path']))
        return list_sessions(request, error_line='Unable to find an image file at {0}'.format(request.POST['sess_path']))

    # Get a list of plugins we can use. and prepopulate the list.

    # Profile

    if 'profile' in request.POST:
        if request.POST['profile'] != 'AutoDetect':
            profile = request.POST['profile']
            new_session['session_profile'] = profile
        else:
            profile = None

    vol_int = RunVol(profile, new_session['session_path'])
    #print "{}".format(dir(vol_int))
    image_info = {}

    if not profile:

        imageinfo = vol_int.run_plugin('imageinfo')

        imageinfo_text = imageinfo['rows'][0][0]

        # ImageInfo tends to error with json so parse text manually.

        image_info = {}
        for line in imageinfo_text.split('\n'):
            try:
                key, value = line.split(' : ')
                image_info[key.strip()] = value.strip()
            except Exception as e:
                print 'Error Getting imageinfo: {0}'.format(e)

        profile = image_info['Suggested Profile(s)'].split(',')[0]

        # Re initialize with correct profile
        vol_int = RunVol(profile, new_session['session_path'])

    # Get compatible plugins

    plugin_list = vol_int.list_plugins()

    new_session['session_profile'] = profile

    new_session['image_info'] = image_info

    # Plugin Options
    plugin_filters = vol_interface.plugin_filters

    # Store it
    session_id = db.create_session(new_session)

    # For each plugin create the entry
    for plugin in plugin_list:
        db_results = {}
        db_results['session_id'] = session_id
        plugin_name = plugin[0]
        db_results['plugin_name'] = plugin_name

        # Ignore plugins we cant handle
        if plugin_name in plugin_filters['drop']:
            continue

        db_results['help_string'] = plugin[1]
        db_results['created'] = None
        db_results['plugin_output'] = None
        db_results['status'] = None
        # Write to DB
        db.create_plugin(db_results)
	
    return redirect('/session/{0}'.format(str(session_id)))


def plugin_output(plugin_id):
    plugin_id = ObjectId(plugin_id)
    plugin_data = db.get_pluginbyid(plugin_id)

    # Convert Int to Hex Here instead of plugin for now.

    try:

        for x in ['Offset', 'Offset(V)', 'Offset(P)', 'Process(V)', 'ImageBase', 'Base']:

            if x in plugin_data['plugin_output']['columns']:
                row_loc = plugin_data['plugin_output']['columns'].index(x)

                for row in plugin_data['plugin_output']['rows']:
                    row[row_loc] = hex(row[row_loc])
    except Exception as e:
        logger.error('Error converting hex a: {0}'.format(e))

    return plugin_data['plugin_output']


def run_plugin(session_id, plugin_id):

    target_pid = None
    dump_dir = None
    dump_dir = None
    error = None
    plugin_id = ObjectId(plugin_id)
    sess_id = ObjectId(session_id)

    if sess_id and plugin_id:

        # Get details from the session
        session = db.get_session(sess_id)
        # Get details from the plugin
        plugin_row = db.get_pluginbyid(ObjectId(plugin_id))

        plugin_name = plugin_row['plugin_name'].lower()

        logger.debug('Running Plugin: {0}'.format(plugin_name))

        # Set plugin status
        new_values = {'status': 'processing'}
        db.update_plugin(ObjectId(plugin_id), new_values)

        # set vol interface
        vol_int = RunVol(session['session_profile'], session['session_path'])

        # Run the plugin with json as normal
        output_style = 'json'
        try:
            results = vol_int.run_plugin(plugin_name, output_style=output_style)
        except Exception as error:
            results = False
            logger.error('Json Output error in {0} - {1}'.format(plugin_name, error))

        if 'unified output format has not been implemented' in str(error) or 'JSON output for trees' in str(error):
            output_style = 'text'
            try:
                results = vol_int.run_plugin(plugin_name, output_style=output_style)
                error = None
            except Exception as error:
                logger.error('Json Output error in {0}, {1}'.format(plugin_name, error))
                results = False


        # If we need a DumpDir
        if '--dump-dir' in str(error) or 'specify a dump directory' in str(error):
            # Create Temp Dir
            logger.debug('{0} - Creating Temp Directory'.format(plugin_name))
            temp_dir = tempfile.mkdtemp()
            dump_dir = temp_dir
            try:
                results = vol_int.run_plugin(plugin_name, dump_dir=dump_dir, output_style=output_style)
            except Exception as error:
                results = False
                # Set plugin status
                new_values = {'status': 'error'}
                db.update_plugin(ObjectId(plugin_id), new_values)
                logger.error('Error: Unable to run plugin {0} - {1}'.format(plugin_name, error))


        # Check for result set
        if not results:
            # Set plugin status
            new_values = {'status': 'error'}
            db.update_plugin(ObjectId(plugin_id), new_values)
            return 'Error: Unable to run plugin {0} - {1}'.format(plugin_name, error)



        ##
        # Files that dump output to disk
        ##

        if dump_dir:
            file_list = os.listdir(temp_dir)
            '''
            I need to process the results and the items in the dump dir.

            Add Column for ObjectId

            Store the file in the GridFS get an ObjectId
            add the ObjectId to the rows, each has a differnet column format so this could be a pain.

            '''

            # Add Rows

            if plugin_row['plugin_name'] == 'dumpfiles':
                for row in results['rows']:
                    try:
                        filename = row[3]
                        file_data = row[-1].decode('hex')
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, sess_id, sha256, filename)
                        row[-1] = '<a class="text-success" href="#" ' \
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">' \
                                  'File Details</a>'

                    except Exception as error:
                        row[-1] = 'Not Stored: {0}'.format(error)

            if plugin_row['plugin_name'] in ['procdump', 'dlldump']:
                # Add new column
                results['columns'].append('StoredFile')
                for row in results['rows']:
                    if row[-1].startswith("OK"):
                        filename = row[-1].split("OK: ")[-1]
                        if filename in file_list:
                            file_data = open(os.path.join(temp_dir, filename), 'rb').read()
                            sha256 = hashlib.sha256(file_data).hexdigest()
                            file_id = db.create_file(file_data, sess_id, sha256, filename)
                            row.append('<a class="text-success" href="#" '
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">'
                                  'File Details</a>')
                    else:
                        row.append('Not Stored')

            if plugin_row['plugin_name'] == 'dumpregistry':
                results = {}
                results['columns'] = ['Hive Name', 'StoredFile']
                results['rows'] = []
                for filename in file_list:
                    file_data = open(os.path.join(temp_dir, filename), 'rb').read()
                    sha256 = hashlib.sha256(file_data).hexdigest()
                    file_id = db.create_file(file_data, sess_id, sha256, filename)
                    results['rows'].append([filename, '<a class="text-success" href="#" '
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">'
                                  'File Details</a>'])

            if plugin_row['plugin_name'] in ['dumpcerts']:
                # Add new column
                for row in results['rows']:
                    filename = row[5]
                    if filename in file_list:
                        file_data = open(os.path.join(temp_dir, filename), 'rb').read()
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, sess_id, sha256, filename)
                        row[-1] ='<a class="text-success" href="#" ' \
                              'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">' \
                              'File Details</a>'
                    else:
                        row.append('Not Stored')

            # Remove the dumpdir
            shutil.rmtree(temp_dir)

        ##
        # Extra processing on some outputs
        ##

        # Add option to process hive keys
        if plugin_row['plugin_name'] in ['hivelist', 'hivescan']:
            results['columns'].insert(0, '#')
            results['columns'].append('Extract Keys')

            counter = 0
            for row in results['rows']:
                counter += 1
                row.insert(0, counter)

                ajax_string = "onclick=\"ajaxHandler('hivedetails', {'plugin_id':'"+ str(plugin_id) +"', 'rowid':'"+ str(counter) +"'}, true )\"; return false"
                row.append('<a class="text-success" href="#" '+ ajax_string +'>View Hive Keys</a>')

        # update the plugin
        new_values = {}
        new_values['created'] = datetime.now()
        new_values['plugin_output'] = results
        new_values['status'] = 'completed'
        db.update_plugin(ObjectId(plugin_id), new_values)
        try:
            db.update_plugin(ObjectId(plugin_id), new_values)
            # Update the session
            new_sess = {}
            new_sess['modified'] = datetime.now()
            db.update_session(sess_id, new_sess)

            return plugin_row['plugin_name']

        except Exception as error:
            # Set plugin status
            new_values = {'status': 'error'}
            db.update_plugin(ObjectId(plugin_id), new_values)
            logger.error('Error: Unable to Store Output for {0} - {1}'.format(plugin_name, error))
            return 'Error: Unable to Store Output for {0}- {1}'.format(plugin_name, error)


def file_download(request, query_type, object_id):

    if query_type == 'file':
        file_object = db.get_filebyid(ObjectId(object_id))
        file_name = '{0}.bin'.format(file_object.filename)
        file_data = file_object.read()

    if query_type == 'plugin':
        plugin_object = db.get_pluginbyid(ObjectId(object_id))

        file_name = '{0}.csv'.format(plugin_object['plugin_name'])
        plugin_data = plugin_object['plugin_output']

        # Convert Int to Hex Here instead of plugin for now.
        try:

            for x in ['Offset', 'Offset(V)', 'Offset(P)', 'Process(V)', 'ImageBase', 'Base']:

                if x in plugin_data['columns']:
                    row_loc = plugin_data['columns'].index(x)

                    for row in plugin_data['rows']:
                        row[row_loc] = str(hex(row[row_loc])).rstrip('L')
        except Exception as error:
            logger.error("Error Converting to hex b: {0}".format(error))

        file_data = ""
        file_data += ",".join(plugin_data['columns'])
        file_data += "\n"
        for row in plugin_data['rows']:
            for item in row:
                file_data += "{0},".format(item)
            file_data.rstrip(',')
            file_data += "\n"

    response = HttpResponse(file_data, content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename="{0}"'.format(file_name)
    return response

@csrf_exempt
def ajax_handler(request, command):

    #if command == 'pollplugins':
        #if 'session_id' in request.POST:
            #session_id = request.POST['session_id']
            #plugin_rows = db.get_pluginbysession(ObjectId(session_id))
            #return render(request, 'plugin_poll.html', {'plugin_output': plugin_rows})
        #else:
            #return HttpResponseServerError

    if command == 'dropplugin':
        if 'plugin_id' in request.POST:
            plugin_id = request.POST['plugin_id']
            # update the plugin
            new_values = {'created': None,'plugin_output': None, 'status': None}
            db.update_plugin(ObjectId(plugin_id), new_values)
            return HttpResponse('OK')

    if command == 'runplugin':
        if 'plugin_id' in request.POST and 'session_id' in request.POST:
            plugin_name = run_plugin(request.POST['session_id'], request.POST['plugin_id'])
            return HttpResponse(plugin_name)

    if command == 'plugin_dir':

        # Platform PATH seperator
        seperator = ':'
        if sys.platform.startswith('win'):
            seperator = ';'

        # Set Plugins
        if 'plugin_dir' in request.POST:
            plugin_dir = request.POST['plugin_dir']

            if os.path.exists(volrc_file):
                with open(volrc_file, 'a') as out:
                    output = '{0}{1}'.format(seperator, plugin_dir)
                    out.write(output)
                return HttpResponse(' No Plugin Path Provided')
            else:
                # Create new file.
                with open(volrc_file, 'w') as out:
                    output = '[DEFAULT]\nPLUGINS = {0}'.format(plugin_dir)
                    out.write(output)
                return HttpResponse(' No Plugin Path Provided')
        else:
            return HttpResponse(' No Plugin Path Provided')

    if command == 'filedetails':
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']
            file_object = db.get_filebyid(ObjectId(file_id))
            file_datastore = db.search_datastore({'file_id': ObjectId(file_id)})
            file_meta = {'vt': None, 'string_list': None, 'yara': None }
            for row in file_datastore:

                if 'vt' in row:
                    file_meta['vt'] = row['vt']
                if 'string_list' in row:
                    file_meta['string_list'] = row['string_list']
                if 'yara' in row:
                    file_meta['yara'] = row['yara']

            return render(request, 'file_details.html', {'file_details': file_object,
                                                         'file_id': file_id,
                                                         'file_datastore': file_meta
                                                         })

    if command == 'hivedetails':
        if 'plugin_id' and 'rowid' in request.POST:
            pluginid = request.POST['plugin_id']
            rowid = request.POST['rowid']

            plugin_details = db.get_pluginbyid(ObjectId(pluginid))

            key_name = 'hive_keys_{0}'.format(rowid)

            if key_name in plugin_details:
                hive_details = plugin_details[key_name]
            else:
                session_id = plugin_details['session_id']

                session = db.get_session(session_id)

                plugin_data = plugin_details['plugin_output']

                for row in plugin_data['rows']:
                    if str(row[0]) == rowid:
                        hive_offset = str(row[1])

                # Run the plugin
                vol_int = RunVol(session['session_profile'], session['session_path'])
                hive_details = vol_int.run_plugin('hivedump', hive_offset=hive_offset)

                # update the plugin / session
                new_values = {key_name: hive_details}
                db.update_plugin(ObjectId(ObjectId(pluginid)), new_values)
                # Update the session
                new_sess = {}
                new_sess['modified'] = datetime.now()
                db.update_session(session_id, new_sess)

            return render(request, 'hive_details.html', {'hive_details': hive_details})

    if command == 'dottree':
        session_id = request.POST['session_id']
        session = db.get_session(ObjectId(session_id))
        vol_int = RunVol(session['session_profile'], session['session_path'])
        results = vol_int.run_plugin('pstree', output_style='dot')
        return HttpResponse(results)
     
    if command == 'virustotal':
        if not VT_KEY or not VT_LIB:
            return HttpResponse("Unable to use Virus Total. No Key or Library Missing. Check the Console for details")

        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

            file_object = db.get_filebyid(ObjectId(file_id))
            sha256 = file_object.sha256
            vt = PublicApi(API_KEY)
            response = vt.get_file_report(sha256)

            vt_fields = {}


            if response['results']['response_code'] == 1:
                vt_fields['permalink'] = response['results']['permalink']
                vt_fields['total'] = response['results']['total']
                vt_fields['positives'] = response['results']['positives']
                vt_fields['scandate'] = response['results']['scan_date']

                # Store the results in datastore
                store_data = {}
                store_data['file_id'] = ObjectId(file_id)
                store_data['vt'] = vt_fields

                update = db.create_datastore(store_data)

            return render(request, 'file_details_vt.html', {'vt_results': vt_fields})

    if command == 'yara':
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

        if 'rule_file' in request.POST:
            rule_file = request.POST['rule_file']


        if rule_file and file_id and YARA:
            file_object = db.get_filebyid(ObjectId(file_id))
            file_data = file_object.read()


            if os.path.exists(rule_file):
                rules = yara.compile(rule_file)
                matches = rules.match(data=file_data)
                results = []
                for match in matches:
                    for item in match.strings:
                        results.append({'rule': match.rule, 'offset': item[0], 'string': string_clean_hex(item[2])})

            else:
                return render(request, 'file_details_yara.html', {'yara': None, 'error': 'Could not find Rule File'})

            if len(results) > 0:

                # Store the results in datastore
                store_data = {}
                store_data['file_id'] = ObjectId(file_id)
                store_data['yara'] = results

                update = db.create_datastore(store_data)

            return render(request, 'file_details_yara.html', {'yara': results})

        else:
            return HttpResponse('Either No file ID or No Yara Rule was provided')

    if command == 'strings':
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']
            file_object = db.get_filebyid(ObjectId(file_id))
            file_data = file_object.read()
            regexp = '[\x20\x30-\x39\x41-\x5a\x61-\x7a\-\.:]{4,}'
            string_list = re.findall(regexp, file_data)

            # Store the list in datastore
            store_data = {}
            store_data['file_id'] = ObjectId(file_id)
            store_data['string_list'] = string_list

            # Write to DB
            db.create_datastore(store_data)

            return render(request, 'file_details_strings.html', {'string_list': string_list})

    if command == 'dropsession':
        if 'session_id' in request.POST:
            session_id = ObjectId(request.POST['session_id'])
            db.drop_session(session_id)
            return HttpResponse('OK')
            
    if command == 'memhex':
        if 'session_id' in request.POST:
            session_id = ObjectId(request.POST['session_id'])
            session = db.get_session(session_id)
            mem_path = session['session_path']
            if 'start_offset' and 'end_offset' in request.POST:
                try:
                    start_offset = int(request.POST['start_offset'], 0)
                    end_offset = int(request.POST['end_offset'], 0)
                    hex_cmd = 'hexdump -C -s {0} -n {1} {2}'.format(start_offset, end_offset - start_offset, mem_path)
                    hex_output = hex_dump(hex_cmd)
                    return HttpResponse(hex_output)
                except Exception as e:
                    return HttpResponse(e)

    if command == 'memhexdump':
        if 'session_id' in request.POST:
            session_id = ObjectId(request.POST['session_id'])
            session = db.get_session(session_id)
            mem_path = session['session_path']
            if 'start_offset' and 'end_offset' in request.POST:
                try:
                    start_offset = int(request.POST['start_offset'], 0)
                    end_offset = int(request.POST['end_offset'], 0)
                    mem_file = open(mem_path, 'rb')
                    # Get to start
                    mem_file.seek(start_offset)
                    file_data = mem_file.read(end_offset - start_offset)
                    response = HttpResponse(file_data, content_type='application/octet-stream')
                    response['Content-Disposition'] = 'attachment; filename="{0}-{1}.bin"'.format(start_offset, end_offset)
                    return response
                except Exception as e:
                    logger.error('Error Getting hex dump: {0}'.format(e))

    if command == 'addcomment':
		# Check the Input length
        html_resp = '<div id="comment-block"><table class="table table-striped table-bordered table-hover"><tr><th>Comment</th><th>Date</th><th>Delete</th></tr>'
        if 'session_id' and 'comment_text' in request.POST:
            session_id = request.POST['session_id']
            comment_text = request.POST['comment_text']
            comment_data = {'session_id': ObjectId(session_id), 'comment_text': comment_text, 'date_added': datetime.now()}
            db.create_comment(comment_data)
            # now return all the comments for the ajax update
            for comment in db.get_commentbysession(ObjectId(session_id)):
                html_resp += '<tr><td>{0}</td><td>{1}</td><td><span class="clickable"> <a class="text-danger" href="#" >  <span class="glyphicon glyphicon-trash"></span></a></span></td>'.format(comment['comment_text'], comment['date_added'])
            html_resp +='</div>'
        return HttpResponse(html_resp)
    
    if command == 'dropcomment':
        html_resp = '<div id="comment-block"><table class="table table-striped table-bordered table-hover"><tr><th>Comment</th><th>Date</th><th>Delete</th></tr>'
        if 'comment_id' in request.POST:
			session_id = request.POST['session_id']
			comment_id = ObjectId(request.POST['comment_id'])
			db.delete_comment(comment_id)
						
			# now return all the comments for the ajax update
			for comment in db.get_commentbysession(ObjectId(session_id)):
				html_resp += '<tr><td>{0}</td><td>{1}</td><td><span class="clickable"> <a class="text-danger" href="#" >  <span class="glyphicon glyphicon-trash"></span></a></span></td>'.format(comment['comment_text'], comment['date_added'])
				
			html_resp +='</div>'
        return HttpResponse(html_resp)

    if command == 'searchbar':
        if 'search_type' and 'search_text' and 'session_id' in request.POST:
            search_type = request.POST['search_type']
            search_text = request.POST['search_text']
            session_id = request.POST['session_id']

            if search_type == 'plugin':
                results = {'rows':[]}
                results['columns'] = ['Plugin Name', 'View Results']
                rows = db.search_plugins(search_text, session_id=ObjectId(session_id))
                for row in rows:
                    results['rows'].append([row['plugin_name'], '<a href="#" onclick="ajaxHandler(\'pluginresults\', {{\'plugin_id\':\'{0}\'}}, false ); return false">View Output</a>'.format(row['_id'])])
                return render(request, 'plugin_output.html', {'plugin_results': results})

            if search_type == 'hash':
                pass
            if search_type == 'registry':

                logger.debug('Registry Search')
                try:
                    session = db.get_session(ObjectId(session_id))
                    vol_int = RunVol(session['session_profile'], session['session_path'])
                    results = vol_int.run_plugin('printkey', output_style='json', plugin_options={'KEY': search_text})
                    return render(request, 'plugin_output.html', {'plugin_results': results})
                except Exception as error:
                    logger.error(error)

            if search_type == 'vol':
                # Run a vol command and get the output

                vol_output = getoutput('vol.py {0}'.format(search_text))

                results = {'rows': [['<pre>{0}</pre>'.format(vol_output)]], 'columns': ['Volitlity Raw Output']}

                # Consider storing the output here as well.


                return render(request, 'plugin_output.html', {'plugin_results': results})

            return HttpResponse('No valid search query found.')

    if command == 'pluginresults':
        if 'plugin_id' in request.POST:
            plugin_id = ObjectId(request.POST['plugin_id'])
            plugin_results = plugin_output(plugin_id)
            plugin = db.get_pluginbyid(plugin_id)
            plugin_name = plugin['plugin_name']
            return render(request, 'plugin_output.html', {'plugin_results': plugin_results,
                                                          'plugin_name' : plugin_name})
            
    if command == 'pluginanalysis':
        if 'plugin_id' in request.POST:
            plugin_id = ObjectId(request.POST['plugin_id'])
            plugin = db.get_pluginbyid(plugin_id)
            
            plugin_output_analysis = plugin_output(plugin_id)
            plugin_status = plugin['status']
            plugin_name = plugin['plugin_name']
            count_System = 0
            count_services = 0
            Idle =''
            System_PID =''
            #https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
			#http://www.t1shopper.com/tools/port-number/
            common_port = [0, 1, 2, 3, 5, 7, 9, 11, 13, 17, 19, 20, 21, 22, 23, 24, 25, 27, 29, 31, 33, 35, 37, 38, 39, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 242, 243, 244, 245, 246, 247, 248, 256, 257, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 280, 281, 282, 283, 284, 286, 287, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 333, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 704, 705, 706, 707, 709, 710, 711, 712, 713, 714, 715, 716, 729, 730, 731, 741, 742, 744, 747, 748, 749, 750, 751, 752, 753, 754, 758, 759, 760, 761, 762, 763, 764, 765, 767, 769, 770, 771, 772, 773, 774, 775, 776, 777, 780, 800, 801, 810, 828, 829, 830, 831, 832, 833, 847, 848, 860, 861, 862, 873, 886, 887, 888, 900, 901, 902, 903, 910, 911, 912, 913, 989, 990, 991, 992, 993, 994, 995, 996, 997, 998, 999, 1000, 1010, 1021, 1022, 1023, 1024, 1025, 1026, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150, 1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, 1161, 1162, 1163, 1164, 1165, 1166, 1167, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220, 1221, 1222, 1223, 1224, 1225, 1226, 1227, 1228, 1229, 1230, 1231, 1233, 1234, 1235, 1236, 1237, 1238, 1239, 1240, 1241, 1242, 1243, 1244, 1245, 1246, 1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1259, 1260, 1261, 1262, 1263, 1264, 1265, 1266, 1267, 1268, 1269, 1270, 1271, 1272, 1273, 1274, 1275, 1276, 1277, 1278, 1279, 1280, 1281, 1282, 1283, 1284, 1285, 1286, 1287, 1288, 1289, 1290, 1291, 1292, 1293, 1294, 1295, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1304, 1305, 1306, 1307, 1308, 1309, 1310, 1311, 1312, 1313, 1314, 1315, 1316, 1317, 1318, 1319, 1320, 1321, 1322, 1323, 1324, 1325, 1326, 1327, 1328, 1329, 1330, 1331, 1332, 1333, 1334, 1335, 1336, 1337, 1338, 1339, 1340, 1341, 1342, 1343, 1344, 1345, 1346, 1347, 1348, 1349, 1350, 1351, 1352, 1353, 1354, 1355, 1356, 1357, 1358, 1359, 1360, 1361, 1362, 1363, 1364, 1365, 1366, 1367, 1368, 1369, 1370, 1371, 1372, 1373, 1374, 1375, 1376, 1377, 1378, 1379, 1380, 1381, 1382, 1383, 1384, 1385, 1386, 1387, 1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1396, 1397, 1398, 1399, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1407, 1408, 1409, 1410, 1411, 1412, 1413, 1414, 1415, 1416, 1417, 1418, 1419, 1420, 1421, 1422, 1423, 1424, 1425, 1426, 1427, 1428, 1429, 1430, 1431, 1432, 1433, 1434, 1435, 1436, 1437, 1438, 1439, 1440, 1441, 1442, 1443, 1444, 1445, 1446, 1447, 1448, 1449, 1450, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1459, 1460, 1461, 1462, 1463, 1464, 1465, 1466, 1467, 1468, 1469, 1470, 1471, 1472, 1473, 1474, 1475, 1476, 1477, 1478, 1479, 1480, 1481, 1482, 1483, 1484, 1485, 1486, 1487, 1488, 1489, 1490, 1492, 1493, 1494, 1495, 1496, 1497, 1498, 1499, 1500, 1501, 1502, 1503, 1504, 1505, 1506, 1507, 1508, 1509, 1510, 1511, 1512, 1513, 1514, 1515, 1516, 1517, 1518, 1519, 1520, 1521, 1522, 1523, 1524, 1525, 1526, 1527, 1529, 1530, 1531, 1532, 1533, 1534, 1535, 1536, 1537, 1538, 1539, 1540, 1541, 1542, 1543, 1544, 1545, 1546, 1547, 1548, 1549, 1550, 1551, 1552, 1553, 1554, 1555, 1556, 1557, 1558, 1559, 1560, 1561, 1562, 1563, 1564, 1565, 1566, 1567, 1568, 1569, 1570, 1571, 1572, 1573, 1574, 1575, 1576, 1577, 1578, 1579, 1580, 1581, 1582, 1583, 1584, 1585, 1586, 1587, 1588, 1589, 1590, 1591, 1592, 1593, 1594, 1595, 1596, 1597, 1598, 1599, 1600, 1601, 1602, 1603, 1604, 1605, 1606, 1607, 1608, 1609, 1610, 1611, 1612, 1613, 1614, 1615, 1616, 1617, 1618, 1619, 1620, 1621, 1622, 1623, 1624, 1625, 1626, 1627, 1628, 1629, 1630, 1631, 1632, 1633, 1634, 1635, 1636, 1637, 1638, 1639, 1640, 1641, 1642, 1643, 1644, 1645, 1646, 1647, 1648, 1649, 1650, 1651, 1652, 1653, 1654, 1655, 1656, 1657, 1658, 1659, 1660, 1661, 1662, 1663, 1664, 1665, 1666, 1667, 1668, 1669, 1670, 1671, 1672, 1673, 1674, 1675, 1676, 1677, 1678, 1679, 1680, 1681, 1682, 1683, 1684, 1685, 1686, 1687, 1688, 1689, 1690, 1691, 1692, 1693, 1694, 1695, 1696, 1697, 1698, 1699, 1700, 1701, 1702, 1703, 1704, 1705, 1706, 1707, 1708, 1709, 1710, 1711, 1712, 1713, 1714, 1715, 1716, 1717, 1718, 1719, 1720, 1721, 1722, 1723, 1724, 1725, 1726, 1727, 1728, 1729, 1730, 1731, 1732, 1733, 1734, 1735, 1736, 1737, 1738, 1739, 1740, 1741, 1742, 1743, 1744, 1745, 1746, 1747, 1748, 1749, 1750, 1751, 1752, 1754, 1755, 1756, 1757, 1758, 1759, 1760, 1761, 1762, 1763, 1764, 1765, 1766, 1767, 1768, 1769, 1770, 1771, 1772, 1773, 1774, 1776, 1777, 1778, 1779, 1780, 1781, 1782, 1784, 1785, 1786, 1787, 1788, 1789, 1790, 1791, 1792, 1793, 1794, 1795, 1796, 1797, 1798, 1799, 1800, 1801, 1802, 1803, 1804, 1805, 1806, 1807, 1808, 1809, 1810, 1811, 1812, 1813, 1814, 1815, 1816, 1817, 1818, 1819, 1820, 1821, 1822, 1823, 1824, 1825, 1826, 1827, 1828, 1829, 1830, 1831, 1832, 1833, 1834, 1835, 1836, 1837, 1838, 1839, 1840, 1841, 1842, 1843, 1844, 1845, 1846, 1847, 1848, 1849, 1850, 1851, 1852, 1853, 1854, 1855, 1856, 1857, 1858, 1859, 1860, 1861, 1862, 1863, 1864, 1865, 1866, 1867, 1868, 1869, 1870, 1871, 1872, 1873, 1874, 1875, 1876, 1877, 1878, 1879, 1880, 1881, 1882, 1883, 1884, 1885, 1886, 1887, 1888, 1889, 1890, 1891, 1892, 1893, 1894, 1896, 1897, 1898, 1899, 1900, 1901, 1902, 1903, 1904, 1905, 1906, 1907, 1908, 1909, 1910, 1911, 1912, 1913, 1914, 1915, 1916, 1917, 1918, 1919, 1920, 1921, 1922, 1923, 1924, 1925, 1926, 1927, 1928, 1929, 1930, 1931, 1932, 1933, 1934, 1935, 1936, 1937, 1938, 1939, 1940, 1941, 1942, 1943, 1944, 1945, 1946, 1947, 1948, 1949, 1950, 1951, 1952, 1953, 1954, 1955, 1956, 1957, 1958, 1959, 1960, 1961, 1962, 1963, 1964, 1965, 1966, 1967, 1968, 1969, 1970, 1971, 1972, 1973, 1974, 1975, 1976, 1977, 1978, 1979, 1980, 1981, 1982, 1983, 1984, 1985, 1986, 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040, 2041, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 2060, 2061, 2062, 2063, 2064, 2065, 2066, 2067, 2068, 2069, 2070, 2071, 2072, 2073, 2074, 2075, 2076, 2077, 2078, 2079, 2080, 2081, 2082, 2083, 2084, 2085, 2086, 2087, 2088, 2089, 2090, 2091, 2092, 2093, 2094, 2095, 2096, 2097, 2098, 2099, 2100, 2101, 2102, 2103, 2104, 2105, 2106, 2107, 2108, 2109, 2110, 2111, 2112, 2113, 2114, 2115, 2116, 2117, 2118, 2119, 2120, 2121, 2122, 2123, 2124, 2125, 2126, 2127, 2128, 2129, 2130, 2131, 2132, 2133, 2134, 2135, 2136, 2137, 2138, 2139, 2140, 2141, 2142, 2143, 2144, 2145, 2146, 2147, 2148, 2149, 2150, 2151, 2152, 2153, 2154, 2155, 2156, 2157, 2158, 2159, 2160, 2161, 2162, 2163, 2164, 2165, 2166, 2167, 2168, 2169, 2170, 2171, 2172, 2173, 2174, 2175, 2176, 2177, 2178, 2179, 2180, 2181, 2182, 2183, 2184, 2185, 2186, 2187, 2188, 2189, 2190, 2191, 2192, 2193, 2197, 2198, 2199, 2200, 2201, 2202, 2203, 2204, 2205, 2206, 2207, 2208, 2209, 2210, 2211, 2212, 2213, 2214, 2215, 2216, 2217, 2218, 2219, 2220, 2221, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230, 2231, 2232, 2233, 2234, 2235, 2236, 2237, 2238, 2239, 2240, 2241, 2242, 2243, 2244, 2245, 2246, 2247, 2248, 2249, 2250, 2251, 2252, 2253, 2254, 2255, 2256, 2257, 2258, 2260, 2261, 2262, 2263, 2264, 2265, 2266, 2267, 2268, 2269, 2270, 2271, 2272, 2273, 2274, 2275, 2276, 2277, 2278, 2279, 2280, 2281, 2282, 2283, 2284, 2285, 2286, 2287, 2288, 2289, 2290, 2291, 2292, 2293, 2294, 2295, 2296, 2297, 2298, 2299, 2300, 2301, 2302, 2303, 2304, 2305, 2306, 2307, 2308, 2309, 2310, 2311, 2312, 2313, 2314, 2315, 2316, 2317, 2318, 2319, 2320, 2321, 2322, 2323, 2324, 2325, 2326, 2327, 2328, 2329, 2330, 2331, 2332, 2333, 2334, 2335, 2336, 2337, 2338, 2339, 2340, 2341, 2342, 2343, 2344, 2345, 2346, 2347, 2348, 2349, 2350, 2351, 2352, 2353, 2354, 2355, 2356, 2357, 2358, 2359, 2360, 2361, 2362, 2363, 2364, 2365, 2366, 2367, 2368, 2370, 2371, 2372, 2373, 2374, 2381, 2382, 2383, 2384, 2385, 2386, 2387, 2388, 2389, 2390, 2391, 2392, 2393, 2394, 2395, 2396, 2397, 2398, 2399, 2400, 2401, 2402, 2403, 2404, 2405, 2406, 2407, 2408, 2409, 2410, 2411, 2412, 2413, 2414, 2415, 2416, 2417, 2418, 2419, 2420, 2421, 2422, 2423, 2424, 2425, 2427, 2428, 2429, 2430, 2431, 2432, 2433, 2434, 2435, 2436, 2437, 2438, 2439, 2440, 2441, 2442, 2443, 2444, 2445, 2446, 2447, 2448, 2449, 2450, 2451, 2452, 2453, 2454, 2455, 2456, 2457, 2458, 2459, 2460, 2461, 2462, 2463, 2464, 2465, 2466, 2467, 2468, 2469, 2470, 2471, 2472, 2473, 2474, 2475, 2476, 2477, 2478, 2479, 2480, 2481, 2482, 2483, 2484, 2485, 2486, 2487, 2488, 2489, 2490, 2491, 2492, 2493, 2494, 2495, 2496, 2497, 2498, 2499, 2500, 2501, 2502, 2503, 2504, 2505, 2506, 2507, 2508, 2509, 2510, 2511, 2512, 2513, 2514, 2515, 2516, 2517, 2518, 2519, 2520, 2521, 2522, 2523, 2524, 2525, 2526, 2527, 2528, 2529, 2530, 2531, 2532, 2533, 2534, 2535, 2536, 2537, 2538, 2539, 2540, 2541, 2542, 2543, 2544, 2545, 2546, 2547, 2548, 2549, 2550, 2551, 2552, 2553, 2554, 2555, 2556, 2557, 2558, 2559, 2560, 2561, 2562, 2563, 2564, 2565, 2566, 2567, 2568, 2569, 2570, 2571, 2572, 2573, 2574, 2575, 2576, 2577, 2578, 2579, 2580, 2581, 2582, 2583, 2584, 2585, 2586, 2587, 2588, 2589, 2590, 2591, 2592, 2593, 2594, 2595, 2596, 2597, 2598, 2599, 2600, 2601, 2602, 2603, 2604, 2605, 2606, 2607, 2608, 2609, 2610, 2611, 2612, 2613, 2614, 2615, 2616, 2617, 2618, 2619, 2620, 2621, 2622, 2623, 2624, 2625, 2626, 2627, 2628, 2629, 2630, 2631, 2632, 2633, 2634, 2635, 2636, 2637, 2638, 2639, 2640, 2641, 2642, 2643, 2644, 2645, 2646, 2647, 2648, 2649, 2650, 2651, 2652, 2653, 2654, 2655, 2656, 2657, 2658, 2659, 2660, 2661, 2662, 2663, 2664, 2665, 2666, 2667, 2668, 2669, 2670, 2671, 2672, 2673, 2674, 2675, 2676, 2677, 2678, 2679, 2680, 2681, 2683, 2684, 2685, 2686, 2687, 2688, 2689, 2690, 2691, 2692, 2694, 2695, 2696, 2697, 2698, 2699, 2700, 2701, 2702, 2703, 2704, 2705, 2706, 2707, 2708, 2709, 2710, 2711, 2712, 2713, 2714, 2715, 2716, 2717, 2718, 2719, 2720, 2721, 2722, 2723, 2724, 2725, 2726, 2727, 2728, 2729, 2730, 2731, 2732, 2733, 2734, 2735, 2736, 2737, 2738, 2739, 2740, 2741, 2742, 2743, 2744, 2745, 2746, 2747, 2748, 2749, 2750, 2751, 2752, 2753, 2754, 2755, 2756, 2757, 2758, 2759, 2760, 2761, 2762, 2763, 2764, 2765, 2766, 2767, 2768, 2769, 2770, 2771, 2772, 2773, 2774, 2775, 2776, 2777, 2778, 2779, 2780, 2781, 2782, 2783, 2784, 2785, 2786, 2787, 2788, 2789, 2790, 2791, 2792, 2793, 2795, 2796, 2797, 2798, 2799, 2800, 2801, 2802, 2803, 2804, 2805, 2806, 2807, 2808, 2809, 2810, 2811, 2812, 2813, 2814, 2815, 2816, 2817, 2818, 2819, 2820, 2821, 2822, 2823, 2824, 2826, 2827, 2828, 2829, 2830, 2831, 2832, 2833, 2834, 2835, 2836, 2837, 2838, 2839, 2840, 2841, 2842, 2843, 2844, 2845, 2846, 2847, 2848, 2849, 2850, 2851, 2852, 2853, 2854, 2855, 2856, 2857, 2858, 2859, 2860, 2861, 2862, 2863, 2864, 2865, 2866, 2867, 2868, 2869, 2870, 2871, 2872, 2874, 2875, 2876, 2877, 2878, 2879, 2880, 2881, 2882, 2883, 2884, 2885, 2886, 2887, 2888, 2889, 2890, 2891, 2892, 2893, 2894, 2895, 2896, 2897, 2898, 2899, 2900, 2901, 2902, 2903, 2904, 2905, 2906, 2907, 2908, 2909, 2910, 2911, 2912, 2913, 2914, 2915, 2916, 2917, 2918, 2919, 2920, 2921, 2922, 2923, 2924, 2926, 2927, 2928, 2929, 2930, 2931, 2932, 2933, 2934, 2935, 2936, 2937, 2938, 2939, 2940, 2941, 2942, 2943, 2944, 2945, 2946, 2947, 2948, 2949, 2950, 2951, 2952, 2953, 2954, 2955, 2956, 2957, 2958, 2959, 2960, 2961, 2962, 2963, 2964, 2965, 2966, 2967, 2968, 2969, 2970, 2971, 2972, 2973, 2974, 2975, 2976, 2977, 2978, 2979, 2980, 2981, 2982, 2983, 2984, 2985, 2986, 2987, 2988, 2989, 2990, 2991, 2992, 2993, 2994, 2995, 2996, 2997, 2998, 2999, 3000, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060, 3061, 3062, 3063, 3064, 3065, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073, 3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086, 3087, 3088, 3089, 3090, 3091, 3093, 3094, 3095, 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3122, 3123, 3124, 3125, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255, 3256, 3257, 3258, 3259, 3260, 3261, 3262, 3263, 3264, 3265, 3266, 3267, 3268, 3269, 3270, 3271, 3272, 3273, 3274, 3275, 3276, 3277, 3278, 3279, 3280, 3281, 3282, 3283, 3284, 3285, 3286, 3287, 3288, 3289, 3290, 3291, 3292, 3293, 3294, 3295, 3296, 3297, 3298, 3299, 3302, 3303, 3304, 3305, 3306, 3307, 3308, 3309, 3310, 3311, 3312, 3313, 3314, 3315, 3316, 3317, 3318, 3319, 3320, 3321, 3322, 3326, 3327, 3328, 3329, 3330, 3331, 3332, 3333, 3334, 3335, 3336, 3337, 3338, 3339, 3340, 3341, 3342, 3343, 3344, 3345, 3346, 3347, 3348, 3349, 3350, 3351, 3352, 3353, 3354, 3355, 3356, 3357, 3358, 3359, 3360, 3361, 3362, 3363, 3364, 3365, 3366, 3367, 3372, 3373, 3374, 3375, 3376, 3377, 3378, 3379, 3380, 3381, 3382, 3383, 3384, 3385, 3386, 3387, 3388, 3389, 3390, 3391, 3392, 3393, 3394, 3395, 3396, 3397, 3398, 3399, 3400, 3401, 3402, 3405, 3406, 3407, 3408, 3409, 3410, 3411, 3412, 3413, 3414, 3415, 3416, 3417, 3418, 3419, 3420, 3421, 3422, 3423, 3424, 3425, 3426, 3427, 3428, 3429, 3430, 3431, 3432, 3433, 3434, 3435, 3436, 3437, 3438, 3439, 3440, 3441, 3442, 3443, 3444, 3445, 3446, 3447, 3448, 3449, 3450, 3451, 3452, 3453, 3454, 3455, 3456, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3464, 3465, 3466, 3467, 3468, 3469, 3470, 3471, 3472, 3473, 3474, 3475, 3476, 3477, 3478, 3479, 3480, 3481, 3482, 3483, 3484, 3485, 3486, 3487, 3488, 3489, 3490, 3491, 3492, 3493, 3494, 3495, 3496, 3497, 3498, 3499, 3500, 3501, 3502, 3503, 3504, 3505, 3506, 3507, 3508, 3509, 3510, 3511, 3512, 3513, 3514, 3515, 3516, 3517, 3518, 3519, 3520, 3521, 3522, 3523, 3524, 3525, 3526, 3527, 3528, 3529, 3530, 3531, 3532, 3533, 3534, 3535, 3536, 3537, 3538, 3539, 3540, 3541, 3542, 3543, 3544, 3545, 3547, 3548, 3549, 3550, 3551, 3552, 3553, 3554, 3555, 3556, 3557, 3558, 3559, 3560, 3561, 3562, 3563, 3564, 3565, 3566, 3567, 3568, 3569, 3570, 3571, 3572, 3573, 3574, 3575, 3576, 3577, 3578, 3579, 3580, 3581, 3582, 3583, 3584, 3585, 3586, 3587, 3588, 3589, 3590, 3591, 3592, 3593, 3594, 3595, 3596, 3597, 3598, 3599, 3600, 3601, 3602, 3603, 3604, 3605, 3606, 3607, 3608, 3609, 3610, 3611, 3612, 3613, 3614, 3615, 3616, 3617, 3618, 3619, 3620, 3621, 3622, 3623, 3624, 3625, 3626, 3627, 3628, 3629, 3630, 3631, 3632, 3633, 3634, 3635, 3636, 3637, 3638, 3639, 3640, 3641, 3642, 3643, 3644, 3645, 3646, 3647, 3648, 3649, 3650, 3651, 3652, 3653, 3654, 3655, 3656, 3657, 3658, 3659, 3660, 3661, 3662, 3663, 3664, 3665, 3666, 3667, 3668, 3669, 3670, 3671, 3672, 3673, 3674, 3675, 3676, 3677, 3678, 3679, 3680, 3681, 3682, 3683, 3684, 3685, 3686, 3687, 3688, 3689, 3690, 3691, 3692, 3695, 3696, 3697, 3698, 3699, 3700, 3701, 3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710, 3711, 3712, 3713, 3714, 3715, 3716, 3717, 3718, 3719, 3720, 3721, 3722, 3723, 3724, 3725, 3726, 3727, 3728, 3729, 3730, 3731, 3732, 3733, 3734, 3735, 3736, 3737, 3738, 3739, 3740, 3741, 3742, 3743, 3744, 3745, 3746, 3747, 3748, 3749, 3750, 3751, 3752, 3753, 3754, 3755, 3756, 3757, 3758, 3759, 3760, 3761, 3762, 3763, 3764, 3765, 3767, 3768, 3769, 3770, 3771, 3772, 3773, 3774, 3775, 3776, 3777, 3778, 3779, 3780, 3781, 3782, 3783, 3784, 3785, 3786, 3787, 3788, 3789, 3790, 3791, 3792, 3793, 3794, 3795, 3796, 3797, 3798, 3799, 3800, 3801, 3802, 3803, 3804, 3805, 3806, 3807, 3808, 3809, 3810, 3811, 3812, 3813, 3814, 3815, 3816, 3817, 3818, 3819, 3820, 3821, 3822, 3823, 3824, 3825, 3826, 3827, 3828, 3829, 3830, 3831, 3832, 3833, 3834, 3835, 3836, 3837, 3838, 3839, 3840, 3841, 3842, 3843, 3844, 3845, 3846, 3847, 3848, 3849, 3850, 3851, 3852, 3853, 3854, 3855, 3856, 3857, 3858, 3859, 3860, 3861, 3862, 3863, 3864, 3865, 3866, 3867, 3868, 3869, 3870, 3871, 3872, 3873, 3874, 3875, 3876, 3877, 3878, 3879, 3880, 3881, 3882, 3883, 3884, 3885, 3886, 3887, 3888, 3889, 3890, 3891, 3892, 3893, 3894, 3895, 3896, 3897, 3898, 3899, 3900, 3901, 3902, 3903, 3904, 3905, 3906, 3907, 3908, 3909, 3910, 3911, 3912, 3913, 3914, 3915, 3916, 3917, 3918, 3919, 3920, 3921, 3922, 3923, 3924, 3925, 3926, 3927, 3928, 3929, 3930, 3931, 3932, 3933, 3934, 3935, 3936, 3937, 3938, 3939, 3940, 3941, 3942, 3943, 3944, 3945, 3946, 3947, 3948, 3949, 3950, 3951, 3952, 3953, 3954, 3955, 3956, 3957, 3958, 3959, 3960, 3961, 3962, 3963, 3964, 3965, 3966, 3967, 3968, 3969, 3970, 3971, 3972, 3973, 3974, 3975, 3976, 3977, 3978, 3979, 3980, 3981, 3982, 3983, 3984, 3985, 3986, 3987, 3988, 3989, 3990, 3991, 3992, 3993, 3995, 3996, 3997, 3998, 3999, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009, 4010, 4011, 4012, 4013, 4014, 4015, 4016, 4017, 4018, 4019, 4020, 4021, 4022, 4023, 4024, 4025, 4026, 4027, 4028, 4029, 4030, 4031, 4032, 4033, 4034, 4035, 4036, 4037, 4038, 4039, 4040, 4041, 4042, 4043, 4044, 4045, 4046, 4047, 4049, 4050, 4051, 4052, 4053, 4054, 4055, 4056, 4057, 4058, 4059, 4060, 4061, 4062, 4063, 4064, 4065, 4066, 4067, 4068, 4069, 4070, 4071, 4072, 4073, 4074, 4075, 4076, 4077, 4078, 4079, 4080, 4081, 4082, 4083, 4084, 4085, 4086, 4087, 4088, 4089, 4090, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 4102, 4103, 4104, 4105, 4106, 4107, 4108, 4109, 4110, 4111, 4112, 4113, 4114, 4115, 4116, 4117, 4118, 4119, 4121, 4122, 4123, 4124, 4125, 4126, 4127, 4128, 4129, 4130, 4131, 4132, 4133, 4134, 4135, 4136, 4137, 4138, 4139, 4140, 4141, 4142, 4143, 4145, 4146, 4147, 4148, 4149, 4150, 4151, 4152, 4153, 4154, 4155, 4156, 4157, 4158, 4159, 4160, 4161, 4162, 4163, 4164, 4165, 4166, 4167, 4168, 4169, 4170, 4171, 4172, 4174, 4175, 4176, 4177, 4178, 4179, 4180, 4181, 4182, 4183, 4184, 4185, 4186, 4187, 4188, 4189, 4190, 4191, 4192, 4193, 4199, 4200, 4300, 4301, 4302, 4303, 4304, 4305, 4306, 4307, 4308, 4309, 4310, 4311, 4312, 4313, 4320, 4321, 4322, 4323, 4324, 4325, 4326, 4327, 4328, 4329, 4340, 4341, 4342, 4343, 4344, 4345, 4346, 4347, 4348, 4349, 4350, 4351, 4352, 4353, 4354, 4355, 4356, 4357, 4358, 4359, 4360, 4361, 4362, 4368, 4369, 4370, 4371, 4372, 4373, 4374, 4375, 4376, 4377, 4378, 4379, 4389, 4390, 4391, 4392, 4393, 4394, 4395, 4396, 4400, 4401, 4402, 4403, 4404, 4405, 4406, 4407, 4408, 4409, 4410, 4425, 4426, 4427, 4428, 4429, 4430, 4431, 4441, 4442, 4443, 4444, 4445, 4446, 4447, 4448, 4449, 4450, 4451, 4452, 4453, 4454, 4455, 4456, 4457, 4458, 4484, 4485, 4486, 4487, 4488, 4500, 4535, 4536, 4537, 4538, 4545, 4546, 4547, 4548, 4549, 4550, 4551, 4552, 4553, 4554, 4555, 4556, 4557, 4558, 4559, 4566, 4567, 4568, 4569, 4590, 4591, 4592, 4593, 4594, 4595, 4596, 4597, 4598, 4599, 4600, 4601, 4602, 4603, 4658, 4659, 4660, 4661, 4662, 4663, 4664, 4665, 4666, 4667, 4668, 4669, 4670, 4671, 4672, 4673, 4674, 4675, 4676, 4677, 4678, 4679, 4680, 4681, 4682, 4683, 4684, 4685, 4686, 4687, 4688, 4689, 4690, 4691, 4692, 4700, 4701, 4702, 4703, 4704, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4737, 4738, 4739, 4740, 4741, 4742, 4743, 4744, 4745, 4749, 4750, 4751, 4752, 4784, 4785, 4786, 4787, 4788, 4800, 4801, 4802, 4803, 4804, 4827, 4837, 4838, 4839, 4840, 4841, 4842, 4843, 4844, 4845, 4846, 4847, 4848, 4849, 4850, 4851, 4867, 4868, 4869, 4870, 4871, 4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 4894, 4899, 4900, 4901, 4902, 4912, 4913, 4914, 4915, 4937, 4940, 4941, 4942, 4949, 4950, 4951, 4952, 4953, 4969, 4970, 4984, 4985, 4986, 4987, 4988, 4989, 4990, 4991, 4999, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012, 5013, 5014, 5015, 5020, 5021, 5022, 5023, 5024, 5025, 5026, 5027, 5028, 5029, 5030, 5031, 5032, 5042, 5043, 5044, 5045, 5046, 5047, 5048, 5049, 5050, 5051, 5052, 5053, 5054, 5055, 5056, 5057, 5058, 5059, 5060, 5061, 5062, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5071, 5072, 5073, 5074, 5079, 5080, 5081, 5082, 5083, 5084, 5085, 5086, 5090, 5091, 5092, 5093, 5094, 5099, 5100, 5101, 5102, 5103, 5104, 5105, 5111, 5112, 5114, 5115, 5116, 5117, 5133, 5134, 5135, 5136, 5137, 5145, 5146, 5150, 5151, 5152, 5153, 5154, 5155, 5156, 5157, 5161, 5162, 5163, 5164, 5165, 5166, 5167, 5168, 5190, 5191, 5192, 5193, 5194, 5200, 5201, 5202, 5203, 5221, 5222, 5223, 5224, 5225, 5226, 5227, 5228, 5232, 5233, 5234, 5235, 5236, 5237, 5245, 5246, 5247, 5248, 5249, 5250, 5251, 5252, 5253, 5264, 5265, 5269, 5270, 5271, 5272, 5280, 5281, 5282, 5298, 5299, 5300, 5301, 5302, 5303, 5304, 5305, 5306, 5307, 5308, 5309, 5310, 5312, 5313, 5314, 5315, 5316, 5317, 5320, 5321, 5343, 5344, 5349, 5350, 5351, 5352, 5353, 5354, 5355, 5356, 5357, 5358, 5359, 5360, 5361, 5362, 5363, 5397, 5398, 5399, 5400, 5401, 5402, 5403, 5404, 5405, 5406, 5407, 5408, 5409, 5410, 5411, 5412, 5413, 5414, 5415, 5416, 5417, 5418, 5419, 5420, 5421, 5422, 5423, 5424, 5425, 5426, 5427, 5428, 5429, 5430, 5431, 5432, 5433, 5434, 5435, 5436, 5437, 5443, 5453, 5454, 5455, 5456, 5461, 5462, 5463, 5464, 5465, 5500, 5501, 5502, 5503, 5504, 5505, 5506, 5553, 5554, 5555, 5556, 5557, 5566, 5567, 5568, 5573, 5574, 5575, 5579, 5580, 5581, 5582, 5583, 5584, 5585, 5597, 5598, 5599, 5600, 5601, 5602, 5603, 5604, 5605, 5627, 5628, 5629, 5630, 5631, 5632, 5633, 5634, 5635, 5636, 5637, 5671, 5672, 5673, 5674, 5675, 5676, 5677, 5678, 5679, 5680, 5681, 5682, 5683, 5688, 5689, 5693, 5696, 5713, 5714, 5715, 5716, 5717, 5718, 5719, 5720, 5721, 5722, 5723, 5724, 5725, 5726, 5727, 5728, 5729, 5730, 5741, 5742, 5743, 5744, 5745, 5746, 5747, 5748, 5750, 5755, 5757, 5766, 5767, 5768, 5769, 5770, 5771, 5777, 5780, 5781, 5782, 5783, 5784, 5785, 5786, 5787, 5793, 5794, 5813, 5814, 5859, 5863, 5900, 5910, 5911, 5912, 5913, 5963, 5968, 5969, 5984, 5985, 5986, 5987, 5988, 5989, 5990, 5991, 5992, 5999, 6000, 6064, 6065, 6066, 6068, 6069, 6070, 6071, 6072, 6073, 6074, 6075, 6076, 6082, 6083, 6084, 6085, 6086, 6087, 6099, 6100, 6101, 6102, 6103, 6104, 6105, 6106, 6107, 6108, 6109, 6110, 6111, 6112, 6113, 6114, 6115, 6116, 6117, 6121, 6122, 6123, 6124, 6133, 6140, 6141, 6142, 6143, 6144, 6145, 6146, 6147, 6148, 6149, 6159, 6160, 6161, 6162, 6163, 6200, 6222, 6241, 6242, 6243, 6244, 6251, 6252, 6253, 6267, 6268, 6269, 6300, 6301, 6306, 6315, 6316, 6320, 6321, 6322, 6343, 6346, 6347, 6350, 6355, 6360, 6370, 6382, 6389, 6390, 6400, 6401, 6402, 6403, 6404, 6405, 6406, 6407, 6408, 6409, 6410, 6417, 6418, 6419, 6420, 6421, 6432, 6443, 6444, 6445, 6446, 6455, 6456, 6471, 6480, 6481, 6482, 6483, 6484, 6485, 6486, 6487, 6488, 6489, 6500, 6501, 6502, 6503, 6505, 6506, 6507, 6508, 6509, 6510, 6513, 6514, 6515, 6543, 6544, 6547, 6548, 6549, 6550, 6551, 6558, 6566, 6567, 6568, 6579, 6580, 6581, 6582, 6583, 6600, 6601, 6602, 6619, 6620, 6621, 6622, 6623, 6624, 6625, 6626, 6627, 6628, 6632, 6655, 6656, 6657, 6665, 6670, 6671, 6672, 6673, 6678, 6679, 6687, 6688, 6689, 6697, 6701, 6702, 6703, 6704, 6705, 6706, 6714, 6715, 6767, 6768, 6769, 6770, 6771, 6785, 6786, 6787, 6788, 6789, 6790, 6791, 6801, 6817, 6831, 6841, 6842, 6850, 6868, 6888, 6901, 6935, 6936, 6946, 6951, 6961, 6962, 6963, 6964, 6965, 6966, 6969, 6997, 6998, 6999, 7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7011, 7012, 7013, 7014, 7015, 7018, 7019, 7020, 7021, 7022, 7023, 7024, 7025, 7030, 7070, 7071, 7080, 7099, 7100, 7101, 7107, 7121, 7128, 7129, 7161, 7162, 7163, 7164, 7165, 7166, 7167, 7168, 7169, 7170, 7171, 7173, 7174, 7200, 7201, 7227, 7228, 7229, 7237, 7262, 7272, 7273, 7274, 7275, 7276, 7277, 7278, 7279, 7280, 7281, 7282, 7300, 7365, 7391, 7392, 7393, 7394, 7395, 7397, 7400, 7401, 7402, 7410, 7421, 7426, 7427, 7428, 7429, 7430, 7431, 7437, 7443, 7473, 7491, 7500, 7501, 7508, 7509, 7510, 7511, 7542, 7543, 7544, 7545, 7546, 7547, 7548, 7549, 7550, 7560, 7563, 7566, 7569, 7570, 7588, 7624, 7626, 7627, 7628, 7629, 7630, 7631, 7633, 7648, 7672, 7673, 7674, 7675, 7676, 7677, 7680, 7689, 7697, 7700, 7707, 7708, 7720, 7724, 7725, 7726, 7727, 7734, 7738, 7741, 7742, 7743, 7744, 7747, 7777, 7778, 7779, 7781, 7786, 7787, 7789, 7794, 7797, 7798, 7799, 7800, 7801, 7810, 7845, 7846, 7869, 7870, 7871, 7880, 7887, 7900, 7901, 7902, 7903, 7913, 7932, 7933, 7967, 7979, 7980, 7981, 7982, 7997, 7998, 7999, 8000, 8001, 8002, 8003, 8005, 8008, 8019, 8020, 8021, 8022, 8025, 8026, 8032, 8033, 8034, 8040, 8042, 8043, 8044, 8051, 8052, 8053, 8054, 8055, 8056, 8057, 8058, 8059, 8074, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8091, 8097, 8100, 8101, 8115, 8116, 8118, 8121, 8122, 8128, 8129, 8130, 8131, 8132, 8148, 8149, 8160, 8161, 8181, 8182, 8183, 8184, 8192, 8194, 8195, 8199, 8200, 8201, 8204, 8205, 8206, 8207, 8208, 8230, 8243, 8276, 8280, 8292, 8293, 8294, 8300, 8301, 8320, 8321, 8351, 8376, 8377, 8378, 8379, 8380, 8383, 8400, 8401, 8402, 8403, 8404, 8405, 8416, 8417, 8442, 8443, 8444, 8450, 8470, 8471, 8472, 8473, 8474, 8500, 8501, 8554, 8555, 8567, 8600, 8610, 8611, 8612, 8613, 8614, 8686, 8699, 8732, 8733, 8763, 8764, 8765, 8770, 8786, 8787, 8793, 8800, 8804, 8873, 8880, 8883, 8888, 8889, 8890, 8891, 8892, 8893, 8894, 8899, 8900, 8901, 8910, 8911, 8912, 8913, 8937, 8953, 8954, 8989, 8990, 8991, 8999, 9000, 9001, 9002, 9007, 9008, 9009, 9010, 9020, 9021, 9022, 9023, 9024, 9025, 9026, 9050, 9051, 9080, 9082, 9083, 9084, 9085, 9086, 9087, 9088, 9089, 9090, 9091, 9092, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9119, 9131, 9160, 9161, 9162, 9163, 9164, 9191, 9200, 9201, 9202, 9203, 9204, 9205, 9206, 9207, 9208, 9209, 9210, 9211, 9212, 9213, 9214, 9215, 9216, 9217, 9222, 9255, 9278, 9279, 9280, 9281, 9282, 9283, 9284, 9285, 9286, 9287, 9292, 9293, 9294, 9295, 9300, 9306, 9312, 9318, 9321, 9343, 9344, 9346, 9374, 9380, 9387, 9388, 9389, 9390, 9396, 9397, 9400, 9401, 9402, 9418, 9443, 9444, 9450, 9500, 9522, 9535, 9536, 9555, 9592, 9593, 9594, 9595, 9596, 9597, 9598, 9599, 9600, 9612, 9614, 9616, 9617, 9618, 9628, 9629, 9630, 9631, 9632, 9640, 9667, 9668, 9694, 9695, 9700, 9747, 9750, 9753, 9762, 9800, 9801, 9802, 9875, 9876, 9888, 9889, 9898, 9899, 9900, 9901, 9902, 9909, 9911, 9950, 9951, 9952, 9953, 9966, 9987, 9988, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10007, 10008, 10009, 10010, 10050, 10051, 10055, 10080, 10081, 10100, 10101, 10102, 10103, 10104, 10107, 10110, 10113, 10114, 10115, 10116, 10117, 10128, 10129, 10160, 10161, 10162, 10200, 10201, 10252, 10260, 10288, 10321, 10500, 10540, 10541, 10542, 10543, 10544, 10800, 10805, 10809, 10810, 10860, 10990, 11000, 11001, 11104, 11105, 11106, 11111, 11112, 11161, 11162, 11163, 11164, 11165, 11171, 11172, 11174, 11175, 11201, 11208, 11211, 11319, 11320, 11321, 11367, 11371, 11489, 11600, 11720, 11751, 11876, 11877, 11967, 11997, 11998, 11999, 12000, 12001, 12002, 12003, 12004, 12005, 12006, 12007, 12008, 12010, 12012, 12013, 12109, 12121, 12168, 12172, 12300, 12321, 12322, 12345, 12753, 13160, 13216, 13217, 13218, 13223, 13224, 13400, 13720, 13721, 13722, 13724, 13782, 13783, 13785, 13786, 13818, 13819, 13820, 13821, 13822, 13823, 13929, 13930, 14000, 14001, 14033, 14034, 14141, 14142, 14145, 14149, 14150, 14154, 14250, 14414, 14936, 14937, 15000, 15118, 15345, 15363, 15555, 15660, 15740, 15998, 15999, 16000, 16001, 16002, 16003, 16020, 16021, 16161, 16162, 16309, 16310, 16311, 16360, 16361, 16367, 16368, 16384, 16619, 16900, 16950, 16991, 16992, 16993, 16994, 16995, 17007, 17185, 17219, 17234, 17235, 17500, 17729, 17754, 17755, 17756, 17777, 18000, 18104, 18136, 18181, 18182, 18183, 18184, 18185, 18186, 18187, 18241, 18262, 18463, 18634, 18635, 18769, 18881, 18888, 19000, 19020, 19191, 19194, 19283, 19315, 19398, 19410, 19411, 19412, 19539, 19540, 19541, 19998, 19999, 20000, 20001, 20002, 20003, 20005, 20012, 20013, 20014, 20034, 20046, 20048, 20049, 20167, 20202, 20222, 20480, 20670, 20999, 21000, 21553, 21554, 21590, 21800, 21845, 21846, 21847, 21848, 21849, 22000, 22001, 22002, 22003, 22004, 22005, 22125, 22128, 22273, 22305, 22343, 22347, 22350, 22537, 22555, 22763, 22800, 22951, 23000, 23001, 23002, 23003, 23004, 23005, 23272, 23333, 23400, 23401, 23402, 23456, 23457, 24000, 24001, 24002, 24003, 24004, 24005, 24006, 24242, 24249, 24321, 24386, 24465, 24554, 24676, 24677, 24678, 24680, 24754, 24922, 25000, 25001, 25002, 25003, 25004, 25005, 25006, 25007, 25008, 25009, 25471, 25576, 25604, 25793, 25900, 25901, 25902, 25903, 26000, 26133, 26208, 26260, 26261, 26262, 26263, 26486, 26487, 26489, 27000, 27345, 27442, 27504, 27782, 27999, 28000, 28001, 28240, 29118, 29167, 29168, 29169, 30001, 30002, 30260, 30999, 31020, 31029, 31416, 31457, 31620, 31685, 31765, 31948, 31949, 32034, 32249, 32483, 32635, 32636, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32801, 32811, 32896, 33123, 33331, 33333, 33434, 33656, 34249, 34378, 34379, 34567, 34962, 34963, 34964, 34980, 35354, 35355, 35356, 35357, 36001, 36412, 36422, 36443, 36444, 36524, 36865, 37475, 37654, 38201, 38202, 38203, 39681, 40000, 40841, 40842, 40843, 40853, 41111, 41121, 41794, 41795, 42508, 42509, 42510, 43188, 43189, 43190, 43191, 43440, 43441, 44321, 44322, 44323, 44553, 44600, 44818, 45054, 45678, 45825, 45966, 46999, 47000, 47001, 47557, 47624, 47806, 47808, 48000, 48001, 48002, 48003, 48004, 48005, 48049, 48128, 48129, 48556, 48619]
            #http://social.technet.microsoft.com/wiki/contents/articles/4484.windows-7-default-services.aspx
            #https://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/sys_srv_default_settings.mspx
            #https://technet.microsoft.com/en-us/library/cc785922(v=ws.10).aspx    
            common_services = ['Application Experience', 'Application Layer Gateway Service', 'Application Identity', 'Application Information', 'Application Management', 'Windows Audio Endpoint Builder', 'Windows Audio', 'ActiveX Installer', 'BitLocker Drive Encryption Service', 'Base Filtering Engine', 'Background Intelligent Transfer Service',
                               'Computer Browser', 'Bluetooth Support Service', 'Certificate Propagation', 'COM+ System Application', 'Cryptographic Services', 'Offline Files', 'DCOM Server Process Launcher', 'Disk Defragmenter', 'DHCP Client', 'DNS Client, Wired AutoConfig', 'Diagnostic Policy Service', 'Extensible Authentication Protocol',
                               'Encrypting File System (EFS)', 'Windows Media Center Receiver Service', 'Windows Media Center Scheduler Service', 'ETOKSRV, Windows Event Log', 'COM+ Event System', 'Fax, Function Discovery Provider Host', 'Function Discovery Resource Publication', 'Windows Font Cache Service', 'Windows Presentation Foundation Font Cache 3.0.0.0',
                               'Group Policy Client', 'Human Interface Device Access', 'Health Key and Certificate Management', 'HomeGroup Provider', 'Windows CardSpace', 'IKE and AuthIP IPsec Keying Modules', 'PnP-X IP Bus Enumerator', 'IP Helper', 'CNG Key Isolation', 'KtmRm for Distributed Transaction Coordinator',
                               'Server', 'Workstation', 'Link-Layer Topology Discovery Mapper', 'TCP/IP NetBIOS Helper', 'Media Center Extender Service', 'Microsoft SharePoint Workspace Audit Service', 'Multimedia Class Scheduler','Windows Firewall', 'MSCamSvc', 'Distributed Transaction Coordinator', 'Microsoft iSCSI Initiator Service',
                               'Windows Installer', 'Network Access Protection Agent', 'Net Driver HPZ12', 'Netlogon', 'Network Connections', 'Network List Service', 'Net.Tcp Port Sharing Service', 'Network Location Awareness', 'Network Store Interface Service', 'Office Source Engine', 'Office Software Protection Platform',
                               'Peer Networking Identity Manager', 'Peer Networking Grouping', 'Program Compatibility Assistant Service', 'BranchCache', 'Performance Counter DLL Host', 'Performance Logs & Alerts', 'Plug and Play', 'Pml Driver HPZ12', 'PNRP Machine Name Publication Service', 'Peer Name Resolution Protocol',
                               'IPsec Policy Agent, Power', 'User Profile Service', 'Protected Storage', 'Quality Windows Audio Video Experience', 'Remote Access Auto Connection Manager', 'Remote Access Connection Manager', 'Routing and Remote Access', 'Remote Registry', 'RPC Endpoint Mapper', 'Remote Procedure Call (RPC) Locator',
                               'Remote Procedure Call (RPC)', 'Security Accounts Manager', 'Smart Card', 'Task Scheduler', 'Smart Card Removal Policy', 'Windows Backup','Secondary Logon', 'System Event Notification Service','Adaptive Brightness', 'Remote Desktop Configuration', 'Internet Connection Sharing (ICS)', 'Shell Hardware Detection',
                               'SNMP Trap', 'Print Spooler', 'Software Protection', 'SPP Notification Service', 'SSDP Discovery', 'Secure Socket Tunneling Protocol Service', 'Windows Image Acquisition (WIA)', 'Storage Service', 'Microsoft Software Shadow Copy Provider', 'Superfetch', 'Tablet PC Input Service', 'Telephony', 'TPM Base Services',
                               'Remote Desktop Services, Themes', 'Thread Ordering Server', 'Distributed Link Tracking Client', 'Windows Modules Installer', 'VMware Agent Service', 'Interactive Services Detection', 'Remote Desktop Services UserMode Port Redirecto', 'UPnP Device Host', 'Desktop Window Manager Session Manager',
                               'Credential Manager', 'Virtual Disk','Volume Shadow Copy', 'Windows Time', 'Windows Activation Technologies Service', 'Block Level Backup Engine Service', 'Windows Biometric Service', 'Windows Connect Now - Config Registrar', 'Windows Color System', 'Diagnostic Service Host', 'Diagnostic System Host',
                               'WebClient', 'Windows Event Collector', 'Problem Reports and Solutions Control Panel Support', 'Windows Error Reporting Service', 'Windows Defender', 'WinHTTP Web Proxy Auto-Discovery Service', 'Windows Management Instrumentation', 'Windows Remote Management (WS-Management)', 'WLAN AutoConfig',
                               'WMI Performance Adapter', 'Windows Media Player Network Sharing Service', 'Parental Controls', 'Portable Device Enumerator Service', 'Security Center Auto', 'Security Center Auto', 'Windows Update', 'Windows Driver Foundation - User-mode Driver Framework', 'WWAN AutoConfig', 'Alerter', 'Automatic Updates',
                               'ClipBook', 'Error Reporting', 'Event Log', 'Fast User Switching Compatibility', 'Help and Support', 'IMAPI CD-Burning COM', 'Internet Connection Firewall (ICF)', 'Internet Connection Sharing', 'IPSec Services', 'Logical Disk Manager', 'Logical Disk Manager Administrative Service', 'Messenger', 'MS Software Shadow Copy Provider',
                               'Net Logon', 'NetMeeting Remote Desktop Sharing', 'Network DDE', 'Network DDE DSDM', 'Network Location Awareness (NLA)', 'NT LM Security Support Provider', 'Performance Logs and Alerts', 'Portable media serial number', 'QoS RSVP', 'Remote Desktop Help Session Manager', 'Removable Storage', 'Smart Card Helper', 'System Event Notification',
                               'System Restore Service', 'Telnet', 'Terminal Services', 'Uninterruptable Power Supply', 'Universal Plug and Play Device Host', 'Upload Manager', 'Utility Manager', 'Wireless Zero Configuration service', 'Windows Firewall/Internet Connection Sharing (ICS)', 'Distributed File System', 'Distributed Link Tracking Server', 'File Replication',
                               'HTTP SSL', 'IAS Jet Database Access', 'IIS Admin', 'IMAPI CD-Burning COM Service', 'Indexing Service', 'Internet Connection Firewall (ICF)/Internet Connection Sharing (ICS)', 'Intersite Messaging', 'Kerberos Key Distribution Center', 'License Logging', 'MSSQL$UDDI', 'MSSQLserverADHelper', '.NET Framework Support Service', 'Remote Administration Service',
                               'Resultant Set of Policy Provider', 'Simple Mail Transfer Protocol (SMTP)', 'Special Administration Console Helper', 'SQLAGENT$UDDI', 'Terminal Services Session Directory', 'Uninterruptible Power Supply', 'Virtual Disk Service', 'Web Element Manager', 'Windows Management Instrumentation Driver Extensions', 'Windows Media Services', 'Wireless Configuration',
                               'WMI Performance Adapter']
            #https://norfipc.com/inf/variables-entorno.html
			#http://www.rapidee.com/en/environment-variables
			#https://technet.microsoft.com/es-es/library/cc749104(v=ws.10).aspx
            comun_envars = ['ALLUSERSPROFILE', 'APPDATA', 'COMMONPROGRAMFILES', 'CMDCMDLINE', 'CMDEXTVERSION', 'COMPUTERNAME', 'COMSPEC', 'DATE', 'ERRORLEVEL', 'PROCESSOR_LEVEL',
                            'HOMEDRIVE', 'HOMEPATH', 'LOGONSERVER', 'LOCALAPPDATA', 'NUMBER_OF_PROCESSORS', 'OS', 'PATH', 'PATHEXT', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 
                            'PROCESSOR_REVISION', 'PROGRAMDATA', 'PROGRAMFILES', 'PSModulePath', 'PUBLIC', 'RANDOM', 'SYSTEMDRIVE', 'SYSTEMROOT', 'TEMP', 'TMP',
                            'TIME', 'USERNAME', 'USERPROFILE', 'WINDIR', 'ALLUSERSPROFILE', 'APPDATA', 'CLIENTNAME', 'CommonProgramFiles', 'COMPUTERNAME', 'ComSpec', 'HOMEDRIVE',
                            'SystemDrive', 'HOMEPATH', 'Path', 'PATHEXT', 'ProgramFiles', 'SystemRoot', 'Windir', 'CommonProgramFiles', 'COMPUTERNAME', 'ComSpec', 'HOMEDRIVE',
                            'COMMONPROGRAMFILES(x86)', 'PROGRAMFILES(X86)', 'PROMPT', 'SystemRoot', 'ProgramFiles', 'USERSID', 'Windir', 'windir', 'CSIDL_TEMPLATES', 'CSIDL_STARTUP', 'CSIDL_STARTMENU', 'CSIDL_SENDTO',
                            'CSIDL_RECENT', 'CSIDL_PROGRAMS', 'CSIDL_PROFILE', 'CSIDL_PRINTHOOD', 'CSIDL_PRINTERS', 'CSIDL_PLAYLISTS', 'CSIDL_PERSONAL', 'CSIDL_NETWORK', 'CSIDL_NETHOOD', 'CSIDL_MYVIDEO', 'CSIDL_MYPICTURES',
                            'CSIDL_MYMUSIC', 'CSIDL_MYDOCUMENTS', 'CSIDL_LOCAL_APPDATA', 'CSIDL_INTERNET_CACHE', 'CSIDL_INTERNET', 'CSIDL_HISTORY', 'CSIDL_FAVORITES', 'CSIDL_DRIVES', 'CSIDL_DESKTOPDIRECTORY', 'CSIDL_DESKTOP', 'CSIDL_COOKIES',
                            'CSIDL_CONTROLS', 'CSIDL_CONTACTS', 'CSIDL_CONNECTIONS', 'CSIDL_CDBURN_AREA', 'CSIDL_BITBUCKET', 'CSIDL_APPDATA', 'CSIDL_ALTSTARTUP', 'CSIDL_ADMINTOOLS', 'SYSTEM32', 'SYSTEM16', 'PROFILESFOLDER',
                            'DEFAULTUSERPROFILE', 'CSIDL_WINDOWS', 'CSIDL_SYSTEM', 'CSIDL_RESOURCES', 'CSIDL_PROGRAM_FILES_COMMON', 'CSIDL_PROGRAM_FILES', 'CSIDL_PROGRAM_FILES_COMMONX86', 'CSIDL_PROGRAM_FILESX86', 'CSIDL_FONTS', 'CSIDL_DEFAULT_QUICKLAUNCH', 'CSIDL_DEFAULT_TEMPLATES',
                            'CSIDL_DEFAULT_STARTUP', 'CSIDL_DEFAULT_PROGRAMS', 'CSIDL_DEFAULT_STARTMENU', 'CSIDL_DEFAULT_SENDTO', 'CSIDL_DEFAULT_RECENT', 'CSIDL_DEFAULT_MYVIDEO', 'CSIDL_DEFAULT_MYMUSIC', 'CSIDL_DEFAULT_MYPICTURES', 'CSIDL_DEFAULT_MYDOCUMENTS', 'CSIDL_DEFAULT_PERSONAL', 'CSIDL_DEFAULT_INTERNET_CACHE',
                            'CSIDL_DEFAULT_HISTORY', 'CSIDL_DEFAULT_FAVORITES', 'CSIDL_DEFAULT_DOWNLOADS', 'CSIDL_DEFAULT_DOWNLOADS', 'CSIDL_DEFAULT_DOWNLOADS', 'CSIDL_DEFAULT_COOKIES', 'CSIDL_DEFAULT_DESKTOP', 'CSIDL_DEFAULT_APPDATA', 'CSIDL_DEFAULT_APPDATA', 'CSIDL_COMMON_TEMPLATES', 'CSIDL_COMMON_STARTUP',
                            'CSIDL_COMMON_STARTMENU', 'CSIDL_COMMON_PROGRAMS', 'CSIDL_COMMON_PICTURES', 'CSIDL_COMMON_MUSIC', 'CSIDL_COMMON_FAVORITES', 'CSIDL_COMMON_DOCUMENTS', 'CSIDL_DEFAULT_DESKTOP', 'CSIDL_COMMON_DESKTOPDIRECTORY', 'CSIDL_COMMON_DESKTOPDIRECTORY', 'CSIDL_COMMON_DESKTOPDIRECTORY', 'CSIDL_COMMON_ADMINTOOLS'
                            'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMFILES']
            IPs_private = []
            IPs_publics = []
            
            #Analysis atomscan
            atomscan_analysis = []
            if plugin_name == 'atomscan':
                for row in plugin_output_analysis['rows']:
					if '' == str(row[5]):
						atomscan_analysis.append(str(row[0]))
						atomscan_analysis.append(str(row[1]))
						atomscan_analysis.append(str(row[2]))
						atomscan_analysis.append(str(row[3]))
						atomscan_analysis.append(str(row[4]))
						atomscan_analysis.append(str(row[5]))
						atomscan_analysis.append('r')
			#END analysis atomscan  

            #Analysis callbacks
            callbacks_analysis = []
            if plugin_name == 'callbacks':
                for row in plugin_output_analysis['rows']:
					if (".sys" not in str(row[2])) or (".exe" not in str(row[2])) or ("SYS" not in str(row[2])) or (".dll" not in str(row[2])):
						callbacks_analysis.append(str(row[0]))
						callbacks_analysis.append(str(row[1]))
						callbacks_analysis.append(str(row[2]))
						callbacks_analysis.append(str(row[3]))
						callbacks_analysis.append('o')
					if ("UNKNOW" in str(row[2])):
						callbacks_analysis.append(str(row[0]))
						callbacks_analysis.append(str(row[1]))
						callbacks_analysis.append(str(row[2]))
						callbacks_analysis.append(str(row[3]))
						callbacks_analysis.append('r')				
		    #END analysis callbacks    
            
            #Analysis cmdscan
            cmdscan_analysis = []
            if plugin_name == 'cmdscan':
                for row in plugin_output_analysis['rows']:
					if ("sc start" in str(row[13])) or ("sc create" in str(row[13])):
						cmdscan_analysis.append(str(row[0]))
						cmdscan_analysis.append(str(row[1]))
						cmdscan_analysis.append(str(row[2]))
						cmdscan_analysis.append(str(row[3]))
						cmdscan_analysis.append(str(row[4]))
						cmdscan_analysis.append(str(row[5]))
						cmdscan_analysis.append(str(row[6]))
						cmdscan_analysis.append(str(row[7]))
						cmdscan_analysis.append(str(row[8]))
						cmdscan_analysis.append(str(row[9]))
						cmdscan_analysis.append(str(row[10]))
						cmdscan_analysis.append(str(row[11]))
						cmdscan_analysis.append(str(row[12]))
						cmdscan_analysis.append('o')						
		    #END analysis cmdscan      
            
            #Analysis connscan
            connscan_analysis = []
            if plugin_name == 'connscan':
				for row in plugin_output_analysis['rows']:
					ip_LA, port_LA =  str(row[1]).split(":")
					ip_RA, port_RA =  str(row[2]).split(":")
					if (int(port_LA) not in common_port) or (int(port_RA) not in common_port):
						connscan_analysis.append(str(row[0]))
						connscan_analysis.append(str(row[1]))
						connscan_analysis.append(str(row[2]))
						connscan_analysis.append(str(row[3]))
						connscan_analysis.append('o')
					if ip_LA.startswith("10.") or ip_LA.startswith("172.16.")  or ip_LA.startswith("172.17.")  or ip_LA.startswith("172.18.")  or ip_LA.startswith("172.19.")  or ip_LA.startswith("172.20.")  or ip_LA.startswith("172.21.")  or ip_LA.startswith("172.22.")  or ip_LA.startswith("172.23.")  or ip_LA.startswith("172.24.")  or ip_LA.startswith("172.25.")  or ip_LA.startswith("172.26.")  or ip_LA.startswith("172.27.")  or ip_LA.startswith("172.16.")  or ip_LA.startswith("172.28.")  or ip_LA.startswith("172.29.")  or ip_LA.startswith("172.30.")  or ip_LA.startswith("172.31.")  or ip_LA.startswith("192.168.")  or ip_LA.startswith("169.254."):
						IPs_private.append(ip_LA)
					else:
						IPs_publics.append(ip_LA)
					if ip_RA.startswith("10.") or ip_RA.startswith("172.16.")  or ip_RA.startswith("172.17.")  or ip_RA.startswith("172.18.")  or ip_RA.startswith("172.19.")  or ip_RA.startswith("172.20.")  or ip_RA.startswith("172.21.")  or ip_RA.startswith("172.22.")  or ip_RA.startswith("172.23.")  or ip_RA.startswith("172.24.")  or ip_RA.startswith("172.25.")  or ip_RA.startswith("172.26.")  or ip_RA.startswith("172.27.")  or ip_RA.startswith("172.16.")  or ip_RA.startswith("172.28.")  or ip_RA.startswith("172.29.")  or ip_RA.startswith("172.30.")  or ip_RA.startswith("172.31.")  or ip_RA.startswith("192.168.")  or ip_RA.startswith("169.254."):
						IPs_private.append(ip_RA)
					else:
						IPs_publics.append(ip_RA)
				IPs_private = set(IPs_private)
				IPs_publics = set(IPs_publics)
			#END analysis connscan
			
			
			#Analysis consoles
            consoles_analysis = []
            if plugin_name == 'consoles':
                for row in plugin_output_analysis['rows']:
					if ("sc start" in str(row[22])) or ("sc create" in str(row[22])) or ("ftp" in str(row[22])):
						consoles_analysis.append(str(row[0]))
						consoles_analysis.append(str(row[1]))
						consoles_analysis.append(str(row[2]))
						consoles_analysis.append(str(row[6]))
						consoles_analysis.append(str(row[7]))
						consoles_analysis.append(str(row[8]))
						consoles_analysis.append(str(row[9]))
						consoles_analysis.append(str(row[10]))
						consoles_analysis.append(str(row[11]))
						consoles_analysis.append(str(row[12]))
						consoles_analysis.append(str(row[13]))
						consoles_analysis.append(str(row[22]))
						consoles_analysis.append('o')						
		    #END analysis consoles
		    		    
		    #Analysis connections
            connections_analysis = []
            if plugin_name == 'connections':
				for row in plugin_output_analysis['rows']:
					ip_LA, port_LA =  str(row[1]).split(":")
					ip_RA, port_RA =  str(row[2]).split(":")
					if (int(port_LA) not in common_port) or (int(port_RA) not in common_port):
						connections_analysis.append(str(row[0]))
						connections_analysis.append(str(row[1]))
						connections_analysis.append(str(row[2]))
						connections_analysis.append(str(row[3]))
						connections_analysis.append('o')
					if ip_LA.startswith("10.") or ip_LA.startswith("172.16.")  or ip_LA.startswith("172.17.")  or ip_LA.startswith("172.18.")  or ip_LA.startswith("172.19.")  or ip_LA.startswith("172.20.")  or ip_LA.startswith("172.21.")  or ip_LA.startswith("172.22.")  or ip_LA.startswith("172.23.")  or ip_LA.startswith("172.24.")  or ip_LA.startswith("172.25.")  or ip_LA.startswith("172.26.")  or ip_LA.startswith("172.27.")  or ip_LA.startswith("172.16.")  or ip_LA.startswith("172.28.")  or ip_LA.startswith("172.29.")  or ip_LA.startswith("172.30.")  or ip_LA.startswith("172.31.")  or ip_LA.startswith("192.168.")  or ip_LA.startswith("169.254."):
						IPs_private.append(ip_LA)
					else:
						IPs_publics.append(ip_LA)
					if ip_RA.startswith("10.") or ip_RA.startswith("172.16.")  or ip_RA.startswith("172.17.")  or ip_RA.startswith("172.18.")  or ip_RA.startswith("172.19.")  or ip_RA.startswith("172.20.")  or ip_RA.startswith("172.21.")  or ip_RA.startswith("172.22.")  or ip_RA.startswith("172.23.")  or ip_RA.startswith("172.24.")  or ip_RA.startswith("172.25.")  or ip_RA.startswith("172.26.")  or ip_RA.startswith("172.27.")  or ip_RA.startswith("172.16.")  or ip_RA.startswith("172.28.")  or ip_RA.startswith("172.29.")  or ip_RA.startswith("172.30.")  or ip_RA.startswith("172.31.")  or ip_RA.startswith("192.168.")  or ip_RA.startswith("169.254."):
						IPs_private.append(ip_RA)
					else:
						IPs_publics.append(ip_RA)
				IPs_private = set(IPs_private)
				IPs_publics = set(IPs_publics)
		    #END analysis connscan
		    
		    #Analysis deskscan
            deskscan_analysis = []
            deskscan_numWin = 0
            attention_numWin = 'No'
            if plugin_name == 'deskscan':
				for row in plugin_output_analysis['rows']:
					if "WinSta0\Default" in str(row[1]):
						deskscan_numWin = int(row[7])
					if (("winlogon.exe" in str(row[14])) or ("explorer.exe" in str(row[14]))) and ("WinSta0\Default" not in str(row[1])):
						deskscan_analysis.append(str(row[0]))
						deskscan_analysis.append(str(row[1]))
						deskscan_analysis.append(str(row[2]))
						deskscan_analysis.append(str(row[3]))
						deskscan_analysis.append(str(row[4]))
						deskscan_analysis.append(str(row[5]))
						deskscan_analysis.append(str(row[6]))
						deskscan_analysis.append(str(row[7]))
						deskscan_analysis.append(str(row[8]))
						deskscan_analysis.append(str(row[9]))
						deskscan_analysis.append(str(row[10]))
						deskscan_analysis.append(str(row[11]))
						deskscan_analysis.append(str(row[12]))
						deskscan_analysis.append(str(row[13]))
						deskscan_analysis.append(str(row[14]))
						deskscan_analysis.append(str(row[15]))
						deskscan_analysis.append('o')
					if (int(row[5]) != 0) and ("WinSta0\Default" not in str(row[1])):
						deskscan_analysis.append(str(row[0]))
						deskscan_analysis.append(str(row[1]))
						deskscan_analysis.append(str(row[2]))
						deskscan_analysis.append(str(row[3]))
						deskscan_analysis.append(str(row[4]))
						deskscan_analysis.append(str(row[5]))
						deskscan_analysis.append(str(row[6]))
						deskscan_analysis.append(str(row[7]))
						deskscan_analysis.append(str(row[8]))
						deskscan_analysis.append(str(row[9]))
						deskscan_analysis.append(str(row[10]))
						deskscan_analysis.append(str(row[11]))
						deskscan_analysis.append(str(row[12]))
						deskscan_analysis.append(str(row[13]))
						deskscan_analysis.append(str(row[14]))
						deskscan_analysis.append(str(row[15]))
						deskscan_analysis.append('r')
				for row in plugin_output_analysis['rows']:
					if 	deskscan_numWin < int(row[7]):
						attention_numWin = 'Yes'
			#END analysis deskscan
            
            #Analysis dllist
            dllist_analysis_path = []
            if plugin_name == 'dlllist':
              for row in plugin_output_analysis['rows']:
                if "c:\windows\system32" not in str(row[4]):
				    if "C:\WINDOWS\System32" not in str(row[4]):
					    if "C:\WINDOWS\system32" not in str(row[4]):
						    if "C:\Windows\system32" not in str(row[4]):
							    if "C:\Windows\SYSTEM32" not in str(row[4]):
								    if "C:\Windows\System32" not in str(row[4]):
									    dllist_analysis_path.append(str(row[0]))
									    dllist_analysis_path.append(str(row[1]))
									    dllist_analysis_path.append(str(row[4]))
                      
            #P1) Extraer PID de csrss.exe, de services.exe, svchost.exe y Lsass.exe
            
            #P2) Recorre ls filas de plugin_output_analysis
				#Si PID = "uno de los anterior" y "contiene  'su ruta' --> Ok
				#else --> WARNING
            
		
			#Analysis envars
            envars_analysis = []
            if plugin_name == 'envars':
				for row in plugin_output_analysis['rows']:
					if str(row[3]) not in comun_envars:
						  envars_analysis.append(str(row[0]))
						  envars_analysis.append(str(row[1]))
						  envars_analysis.append(str(row[2]))
						  envars_analysis.append(str(row[3]))
						  envars_analysis.append(str(row[4]))
			#END analysis envars
            
			#Analysis getsids
            getsids_analysis = []
            usser_list_dist = []
            if plugin_name == 'getsids':
				usser_list = []
				for row in plugin_output_analysis['rows']:
					usser_list.append(str(row[3]))
				usser_list_dist = set(usser_list)
			#END analysis getsids
			
			#Analysis handles
            handles_analysis = []
            if plugin_name == 'handles':
				for row in plugin_output_analysis['rows']:
					if (str(row[4]) == 'File' and '\Device\Mup' in str(row[5])) or (str(row[4]) == 'File' and '\Device\RawIp' in str(row[5])):
						  handles_analysis.append(str(row[0]))
						  handles_analysis.append(str(row[1]))
						  handles_analysis.append(str(row[2]))
						  handles_analysis.append(str(row[3]))
						  handles_analysis.append(str(row[5]))
						  handles_analysis.append('o')
			#END analysis handles
			
			#Analysis iehistory
            iehistory_analysis = []
            if plugin_name == 'iehistory':
				for row in plugin_output_analysis['rows']:
					if str(row[12]):
						iehistory_analysis.append(str(row[12]))
						iehistory_analysis.append(str(row[0]))
						iehistory_analysis.append(str(row[1]))
						iehistory_analysis.append(str(row[2]))
						iehistory_analysis.append(str(row[3]))
						iehistory_analysis.append(str(row[5]))
						iehistory_analysis.append(str(row[6]))
						iehistory_analysis.append(str(row[7]))
			#END analysis iehistory
			
			#Analysis ldrmodules
            ldrmodules_analysis = []
            if plugin_name == 'ldrmodules':
				for row in plugin_output_analysis['rows']:
					if str(row[3]) == 'False' and str(row[4]) == 'False' and str(row[5]) == 'False':
						  ldrmodules_analysis.append(str(row[0]))
						  ldrmodules_analysis.append(str(row[1]))
						  ldrmodules_analysis.append(str(row[2]))
						  ldrmodules_analysis.append(str(row[6]))
						  ldrmodules_analysis.append('r')
			#END analysis ldrmodules
						
			#Analysis netscan
            netscan_analysis = []
            IPs_v6 = []
            if plugin_name == 'netscan':
				for row in plugin_output_analysis['rows']:
					if "v4" in str(row[1]):
						ip_LA, port_LA =  str(row[2]).split(":")
						ip_FA, port_FA =  str(row[3]).split(":")
						if not (('*' in str(ip_LA)) or ('*' in str(port_LA)) or ('*' in str(ip_FA)) or ('*' in str(port_FA))):
							if (int(port_LA) not in common_port) or (int(port_FA) not in common_port):
								netscan_analysis.append(str(row[0]))
								netscan_analysis.append(str(row[1]))
								netscan_analysis.append(str(row[2]))
								netscan_analysis.append(str(row[3]))
								netscan_analysis.append(str(row[4]))
								netscan_analysis.append(str(row[5]))
								netscan_analysis.append(str(row[6]))
								netscan_analysis.append(str(row[7]))
								netscan_analysis.append('o')
							if ip_LA.startswith("10.") or ip_LA.startswith("172.16.")  or ip_LA.startswith("172.17.")  or ip_LA.startswith("172.18.")  or ip_LA.startswith("172.19.")  or ip_LA.startswith("172.20.")  or ip_LA.startswith("172.21.")  or ip_LA.startswith("172.22.")  or ip_LA.startswith("172.23.")  or ip_LA.startswith("172.24.")  or ip_LA.startswith("172.25.")  or ip_LA.startswith("172.26.")  or ip_LA.startswith("172.27.")  or ip_LA.startswith("172.16.")  or ip_LA.startswith("172.28.")  or ip_LA.startswith("172.29.")  or ip_LA.startswith("172.30.")  or ip_LA.startswith("172.31.")  or ip_LA.startswith("192.168.")  or ip_LA.startswith("169.254."):
								IPs_private.append(ip_LA)
							else:
								IPs_publics.append(ip_LA)
							if ip_FA.startswith("10.") or ip_FA.startswith("172.16.")  or ip_FA.startswith("172.17.")  or ip_FA.startswith("172.18.")  or ip_FA.startswith("172.19.")  or ip_FA.startswith("172.20.")  or ip_FA.startswith("172.21.")  or ip_FA.startswith("172.22.")  or ip_FA.startswith("172.23.")  or ip_FA.startswith("172.24.")  or ip_FA.startswith("172.25.")  or ip_FA.startswith("172.26.")  or ip_FA.startswith("172.27.")  or ip_FA.startswith("172.16.")  or ip_FA.startswith("172.28.")  or ip_FA.startswith("172.29.")  or ip_FA.startswith("172.30.")  or ip_FA.startswith("172.31.")  or ip_FA.startswith("192.168.")  or ip_FA.startswith("169.254."):
								IPs_private.append(ip_FA)
							else:
								IPs_publics.append(ip_FA)
					else:
						IPs_v6.append(str(row[2]))
						IPs_v6.append(str(row[3]))
				IPs_private = set(IPs_private)
				IPs_publics = set(IPs_publics)
				IPs_v6 = set(IPs_v6)
		    #END analysis netscan
			
			
			#Analysis objtypescan
			#https://msdn.microsoft.com/en-us/library/windows/desktop/ms724485(v=vs.85).aspx
			#http://www.reverse-engineering.info/SystemInformation/ObjectManager.pdf
            comun_objtypescan = ['Adapter', 'Callback', 'Controller', 'DebugObject', 'Desktop', 'Device', 'Directory', 'Driver', 'Event', 
                                 'EventPair', 'File', 'IoCompletion', 'Job', 'Key', 'KeyedEvent', 'Mutant', 'Port', 'Process', 'Profile', 
                                 'Section', 'Semaphore', 'SymbolicLink', 'Thread', 'Timer', 'Token', 'Type', 'WaitablePort', 'WindowsStation',
                                 'WMIGuid']
            objtypescan_analysis = []
            if plugin_name == 'objtypescan':
				for row in plugin_output_analysis['rows']:
					if str(row[4]) not in comun_objtypescan:
						  objtypescan_analysis.append(str(row[0]))
						  objtypescan_analysis.append(str(row[1]))
						  objtypescan_analysis.append(str(row[2]))
						  objtypescan_analysis.append(str(row[3]))
						  objtypescan_analysis.append(str(row[4]))
						  objtypescan_analysis.append(str(row[5]))
			#END analysis objtypescan

			#Analysis privs
            privs_analysis = []
            if plugin_name == 'privs':
				for row in plugin_output_analysis['rows']:
					if (str(row[3]) == 'SeBackupPrivilege' or str(row[3]) == 'SeDebugPrivilege' or str(row[3]) == 'SeLoadDriverPrivilege' or str(row[3]) == 'SeChangeNotifyPrivilege' or str(row[3]) == 'SeShutdownPrivilege') and 'Present,Enabled' in str(row[4]) and 'Default' not in str(row[4]):
						  privs_analysis.append(str(row[0]))
						  privs_analysis.append(str(row[1]))
						  privs_analysis.append(str(row[3]))
						  privs_analysis.append(str(row[5]))
						  privs_analysis.append('o')
					elif (str(row[3]) == 'SeBackupPrivilege' or str(row[3]) == 'SeDebugPrivilege' or str(row[3]) == 'SeLoadDriverPrivilege' or str(row[3]) == 'SeChangeNotifyPrivilege' or str(row[3]) == 'SeShutdownPrivilege') and 'Enabled' in str(row[4]) and 'Default' not in str(row[4]) and 'Present' not in str(row[4]):
						privs_analysis.append(str(row[0]))
						privs_analysis.append(str(row[1]))
						privs_analysis.append(str(row[3]))
						privs_analysis.append(str(row[5]))
						privs_analysis.append('r')
			#END analysis privs
          
            #Analysis pslist
            pslist_analysis = []
            if plugin_name == 'pslist':
				for row in plugin_output_analysis['rows']:
					if ".exe" not in str(row[1])  and row[1] != 'System':
						if ".EXE" not in str(row[1]):
						  pslist_analysis.append(str(row[0]))
						  pslist_analysis.append(str(row[1]))
						  pslist_analysis.append(str(row[2]))
						  pslist_analysis.append(str(row[3]))
						  pslist_analysis.append('o')
			#END analysis pslist
			
			#Analysis psscan
            psscan_analysis = []
            if plugin_name == 'psscan':
				for row in plugin_output_analysis['rows']:
					if row[1] == 'cmd.exe':
						cmd_PID = row[2]
					if "Idle" in str(row[1])  or "idle" in str(row[1]):
						Idle = 'r'
					else:
						Idle = 'g'
				
				for row in plugin_output_analysis['rows']:					
					if row[1] == 'System' and row[2] != 4:
						System_PID = 'r'
					else:
						System_PID = 'g'
						
				for row in plugin_output_analysis['rows']:
					if row[3] == cmd_PID:
						psscan_analysis.append(str(row[0]))
						psscan_analysis.append(str(row[1]))
						psscan_analysis.append(str(row[2]))
						psscan_analysis.append(str(row[3]))
						psscan_analysis.append(str(row[4]))
						psscan_analysis.append(str(row[5]))
						psscan_analysis.append(str(row[6]))
			#END analysis psscan
			
			#Analysis psxview
            psxview_analysis = []
            if plugin_name == 'psxview':
				for row in plugin_output_analysis['rows']:
					if row[3] != 'True' or row[4] != 'True' or row[5] != 'True' or row[6] != 'True':
					  psxview_analysis.append(str(row[0]))
					  psxview_analysis.append(str(row[1]))
					  psxview_analysis.append(str(row[2]))
					  if row[3] != row[4]:
						  psxview_analysis.append('o')
					  else:
						  psxview_analysis.append('g')
					  if row[5] == 'False':
						  psxview_analysis.append('o')
					  else:
						  psxview_analysis.append('g')
					  if row[3] != row[4] and row[6] == 'False':
						  psxview_analysis.append('r')
					  else:
						  psxview_analysis.append('g')
			
				for row in plugin_output_analysis['rows']:
					if row[1] == 'System':
						count_System = count_System +1
					if row[1] == 'services.exe':
						count_services = count_services +1
            #END analysis psxview
            
            #Analysis shimcache
            shimcache_analysis_path = []
            if plugin_name == 'shimcache':
              for row in plugin_output_analysis['rows']:
                if "\??\C:\WINDOWS\system32" not in str(row[2]):
				    if "\??\C:\Program Files" not in str(row[2]):
					    if "\??\C:\Documents and Settings" not in str(row[2]):
							if "\??\C:\Windows\system32" not in str(row[2]):
								if "\??\C:\Windows\System32" not in str(row[2]):
									if "\??\C:\Windows\System32" not in str(row[2]):
										if "\??\C:\WINDOWS\System32" not in str(row[2]):
											shimcache_analysis_path.append(str(row[0]))
											shimcache_analysis_path.append(str(row[1]))
											shimcache_analysis_path.append(str(row[2]))
			#END analysis shimcache
			
			#Analysis sockets
			#https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
			#http://www.t1shopper.com/tools/port-number/
            sockets_analysis = []
            if plugin_name == 'sockets':
				for row in plugin_output_analysis['rows']:
					if int(row[2]) not in common_port:
						sockets_analysis.append(str(row[0]))
						sockets_analysis.append(str(row[1]))
						sockets_analysis.append(str(row[2]))
						sockets_analysis.append(str(row[3]))
						sockets_analysis.append(str(row[4]))
						sockets_analysis.append(str(row[5]))
						sockets_analysis.append(str(row[6]))
						sockets_analysis.append('o')
					elif int(row[2]) == 0 and int(row[3]) == 0:
						sockets_analysis.append(str(row[0]))
						sockets_analysis.append(str(row[1]))
						sockets_analysis.append(str(row[2]))
						sockets_analysis.append(str(row[3]))
						sockets_analysis.append(str(row[4]))
						sockets_analysis.append(str(row[5]))
						sockets_analysis.append(str(row[6]))
						sockets_analysis.append('r')
					Adress= str(row[5])
					if Adress.startswith("10.") or Adress.startswith("172.16.")  or Adress.startswith("172.17.")  or Adress.startswith("172.18.")  or Adress.startswith("172.19.")  or Adress.startswith("172.20.")  or Adress.startswith("172.21.")  or Adress.startswith("172.22.")  or Adress.startswith("172.23.")  or Adress.startswith("172.24.")  or Adress.startswith("172.25.")  or Adress.startswith("172.26.")  or Adress.startswith("172.27.")  or Adress.startswith("172.16.")  or Adress.startswith("172.28.")  or Adress.startswith("172.29.")  or Adress.startswith("172.30.")  or Adress.startswith("172.31.")  or Adress.startswith("192.168.")  or Adress.startswith("169.254."):
						IPs_private.append(Adress)
					else:
						IPs_publics.append(Adress)
				IPs_private = set(IPs_private)
				IPs_publics = set(IPs_publics)
		    #END analysis sockets
		    
		    #Analysis sockscan
			#https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
			#http://www.t1shopper.com/tools/port-number/
            sockscan_analysis = []
            if plugin_name == 'sockscan':
				for row in plugin_output_analysis['rows']:
					if int(row[2]) not in common_port:
						sockscan_analysis.append(str(row[0]))
						sockscan_analysis.append(str(row[1]))
						sockscan_analysis.append(str(row[2]))
						sockscan_analysis.append(str(row[3]))
						sockscan_analysis.append(str(row[4]))
						sockscan_analysis.append(str(row[5]))
						sockscan_analysis.append(str(row[6]))
						sockscan_analysis.append('o')
					elif int(row[2]) == 0 and int(row[3]) == 0:
						sockscan_analysis.append(str(row[0]))
						sockscan_analysis.append(str(row[1]))
						sockscan_analysis.append(str(row[2]))
						sockscan_analysis.append(str(row[3]))
						sockscan_analysis.append(str(row[4]))
						sockscan_analysis.append(str(row[5]))
						sockscan_analysis.append(str(row[6]))
						sockscan_analysis.append('r')
					Adress= str(row[5])
					if Adress.startswith("10.") or Adress.startswith("172.16.")  or Adress.startswith("172.17.")  or Adress.startswith("172.18.")  or Adress.startswith("172.19.")  or Adress.startswith("172.20.")  or Adress.startswith("172.21.")  or Adress.startswith("172.22.")  or Adress.startswith("172.23.")  or Adress.startswith("172.24.")  or Adress.startswith("172.25.")  or Adress.startswith("172.26.")  or Adress.startswith("172.27.")  or Adress.startswith("172.16.")  or Adress.startswith("172.28.")  or Adress.startswith("172.29.")  or Adress.startswith("172.30.")  or Adress.startswith("172.31.")  or Adress.startswith("192.168.")  or Adress.startswith("169.254."):
						IPs_private.append(Adress)
					else:
						IPs_publics.append(Adress)
				IPs_private = set(IPs_private)
				IPs_publics = set(IPs_publics)
		    #END analysis sockets

            #Analysis svcscan
            svcscan_analysis = []
            svcscan_disabled_analysis = []
            if plugin_name == 'svcscan':
				for row in plugin_output_analysis['rows']:
					if str(row[5]) not in common_services:
						  svcscan_analysis.append(str(row[0]))
						  svcscan_analysis.append(str(row[1]))
						  svcscan_analysis.append(str(row[2]))
						  svcscan_analysis.append(str(row[3]))
						  svcscan_analysis.append(str(row[4]))
						  svcscan_analysis.append(str(row[5]))
						  svcscan_analysis.append(str(row[6]))
						  svcscan_analysis.append(str(row[7]))
						  svcscan_analysis.append(str(row[8]))
					if (str(row[5]) in common_services) and ('SERVICE_DISABLED' in str(row[2])):
						svcscan_disabled_analysis.append(str(row[0]))
						svcscan_disabled_analysis.append(str(row[1]))
						svcscan_disabled_analysis.append(str(row[2]))
						svcscan_disabled_analysis.append(str(row[3]))
						svcscan_disabled_analysis.append(str(row[4]))
						svcscan_disabled_analysis.append(str(row[5]))
						svcscan_disabled_analysis.append(str(row[6]))
						svcscan_disabled_analysis.append(str(row[7]))
						svcscan_disabled_analysis.append(str(row[8]))
						svcscan_disabled_analysis.append('o')
					elif ('SERVICE_DISABLED' in str(row[2])) and (('Firewall' in str(row[5])) or ('Windows Defender' in str(row[5]))):
						svcscan_disabled_analysis.append(str(row[0]))
						svcscan_disabled_analysis.append(str(row[1]))
						svcscan_disabled_analysis.append(str(row[2]))
						svcscan_disabled_analysis.append(str(row[3]))
						svcscan_disabled_analysis.append(str(row[4]))
						svcscan_disabled_analysis.append(str(row[5]))
						svcscan_disabled_analysis.append(str(row[6]))
						svcscan_disabled_analysis.append(str(row[7]))
						svcscan_disabled_analysis.append(str(row[8]))
						svcscan_disabled_analysis.append('r')
			#END analysis svcscan
            
            #Analysis symlinkscan
            symlinkscan_analysis = []
            if plugin_name == 'symlinkscan':
				for row in plugin_output_analysis['rows']:
					if '\Device\LanmanRedirector' in str(row[5]):
						  symlinkscan_analysis.append(str(row[0]))
						  symlinkscan_analysis.append(str(row[1]))
						  symlinkscan_analysis.append(str(row[2]))
						  symlinkscan_analysis.append(str(row[3]))
						  symlinkscan_analysis.append(str(row[4]))
						  symlinkscan_analysis.append(str(row[5]))
						  symlinkscan_analysis.append('o')
			#END analysis symlinkscan
			
			#Analysis timers
            timers_analysis = []
            if plugin_name == 'timers':
                for row in plugin_output_analysis['rows']:
					#if ("sys" not in str(row[5])) or (".exe" not in str(row[5])) or ("SYS" not in str(row[5])) or ("dll" not in str(row[5])):
					if ".exe" not in str(row[5]):
					  if ".sys" not in str(row[5]):
						  timers_analysis.append(str(row[0]))
						  timers_analysis.append(str(row[1]))
						  timers_analysis.append(str(row[2]))
						  timers_analysis.append(str(row[3]))
						  timers_analysis.append(str(row[4]))
						  timers_analysis.append(str(row[5]))
						  timers_analysis.append('o')
					if ("UNKNOW" in str(row[5])):
						timers_analysis.append(str(row[0]))
						timers_analysis.append(str(row[1]))
						timers_analysis.append(str(row[2]))
						timers_analysis.append(str(row[3]))
						timers_analysis.append(str(row[4]))
						timers_analysis.append(str(row[5]))
						timers_analysis.append('r')				
		    #END analysis timers    
			

            return render(request, 'plugin_analysis.html', {'plugin_output_analysis': plugin_output_analysis,
                                                            'plugin_status' : plugin_status,
                                                            'plugin_name' : plugin_name,
                                                            'atomscan_analysis' : atomscan_analysis,
                                                            'callbacks_analysis' : callbacks_analysis,
                                                            'connscan_analysis' : connscan_analysis,
                                                            'cmdscan_analysis' : cmdscan_analysis,
                                                            'consoles_analysis' : consoles_analysis,
                                                            'connections_analysis' : connections_analysis,
                                                            'IPs_private' : IPs_private,
                                                            'IPs_publics' : IPs_publics,
                                                            'IPs_v6' : IPs_v6,
                                                            'deskscan_analysis' : deskscan_analysis,
                                                            'attention_numWin' : attention_numWin,
                                                            'dllist_analysis_path' : dllist_analysis_path,
                                                            'envars_analysis' : envars_analysis,
                                                            'getsids_analysis' : getsids_analysis,
                                                            'handles_analysis' : handles_analysis,
                                                            'usser_list_dist' : usser_list_dist,
                                                            'iehistory_analysis' : iehistory_analysis,
                                                            'ldrmodules_analysis' : ldrmodules_analysis,
                                                            'netscan_analysis' : netscan_analysis,
                                                            'objtypescan_analysis' : objtypescan_analysis,
                                                            'privs_analysis' : privs_analysis,
                                                            'pslist_analysis' : pslist_analysis,
                                                            'Idle' : Idle,
                                                            'System_PID' : System_PID,
                                                            'psscan_analysis' : psscan_analysis,
                                                            'psxview_analysis' : psxview_analysis,
                                                            'count_System' : count_System,
                                                            'count_services' : count_services,
                                                            'shimcache_analysis_path' : shimcache_analysis_path,
                                                            'sockets_analysis' : sockets_analysis,
                                                            'sockscan_analysis' : sockscan_analysis,
                                                            'svcscan_analysis' : svcscan_analysis,
                                                            'svcscan_disabled_analysis' : svcscan_disabled_analysis,
                                                            'symlinkscan_analysis' : symlinkscan_analysis,
                                                            'timers_analysis' : timers_analysis})    

    return HttpResponse('No valid search query found.')
