 # File: ~/CA/ca/ca_env_source.sh
 # Usage: cd ~/CA/ca/ ; source  ~/CA/ca/ca_env_source.sh
 # Modify the default settings to suit your needs.

 echo "Setting conveneince env variables for CSP."

 # These two env are required for CSP to work
 export OPENSSL="$(which openssl)"  # need this for anything to work
 export CSPHOME="$(pwd)"            # cd into ca root directory first

 # These are shortcuts for command line construction
 export CSPROG="/usr/local/bin/csp" # set to whereever the software is
 export CSPCA="CA_ISSUER_01"        # The Issuing CA - also kept offline
 export CSPCAROOT="CA_ROOT"         # The offline root CA
 export CSPCDAYS=1827               # The program default is 365 days
 export CSPDIGEST="SHA512"          # Do not use SHA1
 export CSPKEYSIZE=4096             # Now 4096 is the default CSP.pm value
 export CSPTYPE="server"            # One of: objsign, server or user
 export CSPSAVE=$(date -u +%Y%m%d%H%M%SZ)
 export CSPSTARTDATE=$(date +%Y%m%d%H%M%SZ)
 export CSPENDDATE=$(date -d +"$CSPCDAYS"days +%Y%m%d235959Z)
 x=$CSPSTARTDATE
 DS=$(date -d"${x:0:8} ${x:8:2}:${x:10:2}:${x:12:3}")
 x=$CSPENDDATE
 DX=$(date -d"${x:0:8} ${x:8:2}:${x:10:2}:${x:12:3}")
 export CSPDAYSDIFF=$(expr $(expr $(date '+%s' -d "${DX}") - $(date '+%s' -d "${DS}")) / 86400 + 1)

 # These are the common name (CN)  elements
 # Change these to suit local needs
 export CNOU='Our Organisational Unit'    # The responsible internal unit
 export CNON='Our Organisations Name'     # Our organisation's name
 export CNLO='Our City'                   # Municipality of registration
 export CNST='Our Region'                 # Province, region or state
 export CNCO='CA'                         # Country code of registration
 export CNEM='certificates@example.com'   # CA email

 # Domain names are case insensitive but are made all lowercase by convention.
 export DCHN='ca'                 # set hostname for dns
 export DCLO="${CNLO,,}"          # force domain name location to all lowercase
 export DCDN='example'            # our domain name
 export DCTL='com'                # our registry top level authority

 cat <<-EOM

 To manually initialise a CA follow these steps:


 1. Generate the CA key:

 openssl genrsa -out /path/to/csp/CA/private/ca.key 4096

 2. Generate a signing request for this key:

 openssl req -new \\
    -key /path/to/csp/CA/private/ca.key \\
    -out /path/to/csp/CA/csrs/ca.csr

 3. Self sign the request:
    This method permits specifying the exact date and time
    of the certificate's effective and expiry.

 openssl ca \\
    -selfsign \\
    -config    /path/to/csp/CA/tmp/X.conf \\
    -startdate 20161101000000Z \\
    -enddate   20171031235959Z \\
    -cert      /path/to/csp/CA/ca.crt \\
    -keyfile   /path/to/csp/CA/private/ca.key \\
    -out       /path/to/csp/CA/certs/revised_cert.crt \\
    -infiles   /path/to/csp/csrs/clientcert.csr


 The following can be used to determine date offsets
 to end-of-day UTC of the spcified date:

EOM

 echo 'export TDATE=20361031;'
 echo 'EDAYS=$(expr $(expr $(date '+%s' -d $TDATE) - $(date '+%s')) / 86400);'
 echo 'echo $EDAYS; EDATE="$(date +%F -u -d "$EDAYS days") 23:59:59";'
 echo 'echo $EDATE; NDATE=$(date -u "+%F %T %Z" -d "$EDATE"); echo $NDATE;'


cat <<-EOM

 Issuing a private key and matching certificate with start and end dates
 specified using the convenience environment variables:

 export CSPTYPE=user
 export CSPSTARTDATE=$CSPSTARTDATE
 export CSPENDDATE=$CSPENDDATE
 export CNEM='user_email@example.com'
 export DCHN='User N. Ame'

 csp \$CSPCA issue \\
    --type=\$CSPTYPE \\
    --keysize=\$CSPKEYSIZE \\
    --digest=\$CSPDIGEST \\
    --startdate=\$CSPSTARTDATE \\
    --enddate=\$CSPENDDATE \\
    --email=\$CNEM \\
    --url=ca.example.com \\
    "CN=\$DCHN.\$DCLO.\$DCDN.\$DCTL,OU=\$CNOU,O=\$CNON,L=\$CNLO,ST=\$CNST,C=\$CNCO,DC=\$DCLO,DC=\$DCDN,DC=\$DCTL"

EOM

 echo "The following convenience env variables are now set as displayed below:"
 env | grep -E "^CN|^CS|^DC|^OPENSSL" | sort
 echo ""

 echo "The Distinguished Name (DN) constructed from these variables is:"
 echo \"CN=$DCHN.$DCLO.$DCDN.$DCTL,OU=$CNOU,O=$CNON,L=$CNLO,ST=$CNST,C=$CNCO,DC=$DCLO,DC=$DCDN,DC=$DCTL\"

 echo "The env variable start and end dates for certificates are:"
 echo "    CSPCDAYS: $CSPCDAYS"
 echo "CSPSTARTDATE: $CSPSTARTDATE"
 echo "  CSPENDDATE: $CSPENDDATE"


