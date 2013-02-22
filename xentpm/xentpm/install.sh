
#!/bin/bash

#create a tpm agent dir
ROOT=$1
LOG= $ROOT"/tmp/xen_tpm_agent.log"
BASE= $ROOT"/opt/xensource/tpm"
PLUGIN= $ROOT"/etc/xapi.d/plugins/"

if ! [ -d $BASE ];
    then 
    mkdir -p $BASE
    touch $LOG	
fi 
if ! [ -d $PLUGIN ];
    then 
    mkdir -p $BASE
fi 

## copy schema file
cp -f xenaik.xml $BASE

## copy all executables in /opt/xensource/tpm
cp -f mkcert      $BASE
cp -f aikpublish  $BASE
cp -f aikrespond  $BASE
cp -f xenquote    $BASE

# copy python plugins in the /etc/xapi.d/plugins
cp -f tpmChallangeAik       $PLUGIN
cp -f tpmGetAttestationKey  $PLUGIN
cp -f tpmGetQuote           $PLUGIN
