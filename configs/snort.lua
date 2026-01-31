---------------------------------------------------------------------------
-- Snort 3 Configuration for One_Blink
-- Purpose: IDS/IPS analysis for PCAP files
-- Rules: Snort 3 Community Rules
---------------------------------------------------------------------------
-- PCAP mode configuration
---------------------------------------------------------------------------
pcap = {
    -- Read from PCAP file (set via command line -r)
}

---------------------------------------------------------------------------
-- Network Variables (MUST be defined before IPS module)
---------------------------------------------------------------------------
HOME_NET = 'any'
EXTERNAL_NET = 'any'
DNS_SERVERS = 'any'
SMTP_SERVERS = 'any'
HTTP_SERVERS = 'any'
SQL_SERVERS = 'any'
TELNET_SERVERS = 'any'
SSH_SERVERS = 'any'
FTP_SERVERS = 'any'
SIP_SERVERS = 'any'
HTTP_PORTS = '80,81,82,83,84,85,86,87,88,89,90,311,383,591,593,631,801,808,818,901,972,1158,1220,1414,1533,1741,1830,1942,2231,2301,2381,2809,2980,3029,3037,3057,3128,3443,3702,4000,4343,4848,5000,5117,5250,5450,5600,5814,6080,6173,6988,7000,7001,7005,7071,7144,7145,7510,7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,8028,8040,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,8222,8243,8280,8300,8333,8344,8400,8443,8500,8509,8787,8800,8888,8899,8983,9000,9002,9060,9080,9090,9091,9111,9290,9443,9447,9710,9788,9999,10000,10080,10088,11371,12601,13014,15489,29991,33300,34412,34443,34444,40007,41080,44449,50000,50002,51423,53,55555,56712'
SHELLCODE_PORTS = '!80'
ORACLE_PORTS = '1024:'
SSH_PORTS = '22'
FTP_PORTS = '21,2100,3535'
SIP_PORTS = '5060,5061,5600'
FILE_DATA_PORTS = '$HTTP_PORTS,110,143'
GTP_PORTS = '2123,2152,3386'
MODBUS_PORTS = '502'
DNP3_PORTS = '20000'
AIM_SERVERS = 'any'

-- IPS module configuration
---------------------------------------------------------------------------
ips = {
    -- Enable detection
    enable_builtin_rules = true,
    
    -- Include community rules
    include = '/home/mark/Downloads/snort3-community-rules (2)/snort3-community.rules',
}

-- Network inspection
---------------------------------------------------------------------------
stream = {
    -- Track TCP sessions
}

stream_tcp = {
    -- TCP session tracking
}

stream_udp = {
    -- UDP session tracking
}

stream_ip = {
    -- IP defragmentation
}

-- Protocol decoders
---------------------------------------------------------------------------
-- Enable all protocol decoders
normalizer = { }
ftp_server = { }
ftp_client = { }
ftp_data = { }
telnet = { }
smtp = { }
pop = { }
imap = { }
http_inspect = { }
http2_inspect = { }
sip = { }
ssh = { }
ssl = { }
dns = { }
dce_smb = { }
dce_tcp = { }
dce_udp = { }
dce_rpc = { }
modbus = { }
dnp3 = { }
gtp_inspect = { }

-- Output configuration
---------------------------------------------------------------------------
alert_fast = {
    -- Fast alert format (one line per alert)
    file = true,
}

alert_full = {
    -- Full alert format (detailed)
    file = true,
}

-- Logging
---------------------------------------------------------------------------
event_queue = {
    max_queue = 8,
    log = 8,
}

-- DAQ (Data Acquisition) module
---------------------------------------------------------------------------
daq = {
    module_dirs = {
        '/usr/local/lib/daq',
    },
    modules = {
        {
            name = 'pcap',
            mode = 'read-file',
        }
    },
}

-- Performance statistics
---------------------------------------------------------------------------
perf_monitor = {
    -- Disabled for PCAP analysis to reduce overhead
}

-- Detection engine
---------------------------------------------------------------------------
detection = {
    -- Search method
    search_method = 'ac_full',
    
    -- Split any/any rules
    split_any_any = true,
    
    -- Max queue events
    max_queue_events = 5,
}

-- Profiler (for debugging)
---------------------------------------------------------------------------
profiler = {
    -- Disabled by default
}

---------------------------------------------------------------------------
-- End of Snort 3 Configuration
---------------------------------------------------------------------------
