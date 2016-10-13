 # File: ~/CA/ca/ca_env_source.sh
 # Usage: cd ~/CA/ca/ ; source  ~/CA/ca/ca_env_source.sh

 echo "Setting conveneince env variables for CSP."

 # These two env are required for CSP to work
 export OPENSSL="$(which openssl)"  # need this for anything to work
 export CSPHOME="$(pwd)"            # cd into ca root directory first

 # These are shortcuts for command line construction
 export CSPROG="/root/bin/csp034/csp"
 export CSPCA="CA_HLL_ISSUER_01"    # The Issueing CA - also kept offline
 export CSPCAROOT="CA_HLL_ROOT"     # The offline root CA
 export CSPCDAYS=1827               # The program default is 365 days
 export CSPDIGEST="SHA512"          # Do not use SHA1 
 export CSPKEYSIZE=4096             # Now 4096 is the default CSP.pm value
 export CSPTYPE="server"            # One of: objsign, server or user
 export CSPSAVE=$(date -u +%Y%m%d%H%M%SZ)
 export CSPSTARTDATE=$(date +%Y%m%d%H%M%SZ)
 export CSPENDDATE=$(date -d +"$CSPCDAYS"days +%Y%m%d000000Z)
 x=$CSPSTARTDATE
 DS=$(date -d"${x:0:8} ${x:8:2}:${x:10:2}:${x:12:3}")
 x=$CSPENDDATE
 DX=$(date -d"${x:0:8} ${x:8:2}:${x:10:2}:${x:12:3}")
 export CSPDAYSDIFF=$(expr $(expr $(date '+%s' -d "${DX}") - $(date '+%s' -d "${DS}")) / 86400 + 1)

 # These are the common name (CN)  elements
 export CNOU='Networked Data Services'    # The responsible internal unit
 export CNON='Harte & Lyne Limited'       # Our organisation's name
 export CNLO='Hamilton'                   # Municipality of registration
 export CNST='Ontario'                    # Region of registration
 export CNCO='CA'                         # Country code of registration
 export CNEM='certificates@harte-lyne.ca' # CA email

 # Domain names are case insensitive but are made all lowercase by convention.
 export DCHN='ca'                 # set hostname for dns
 export DCLO="${CNLO,,}"          # force domain name location to all lowercase
 export DCDN='harte-lyne'         # our domain name
 export DCTL='ca'                 # our registry top level authority

 echo "The following convenience env variables are now set as displayed below:"
 env | grep -E "^CN|^CS|^DC" | sort

 echo "The Distinguished Name (DN) constructed from these variables is:"
 echo \"CN=$DCHN.$DCLO.$DCDN.$DCTL,OU=$CNOU,O=$CNON,L=$CNLO,ST=$CNST,C=$CNCO,DC=$DCLO,DC=$DCDN,DC=$DCTL\"

 echo "The env variable start and end dates for certificates are:"
 echo "    CSPCDAYS: $CSPCDAYS"
 echo "CSPSTARTDATE: $CSPSTARTDATE"
 echo "  CSPENDDATE: $CSPENDDATE"

 
