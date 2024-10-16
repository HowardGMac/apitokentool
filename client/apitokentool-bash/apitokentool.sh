#!/bin/bash
# apiTokenTool Information
apiTokenToolURL="{API URL}"
apiTokenKeyPreferenceDomain="{PREFERENCE DOMAIN}"

# Get macOS computer serial, apitokentool signing info and apitokentool access key
deviceSerial=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}')
apiTokenToolSource=${BASH_SOURCE:-$0}
apiTokenToolSigning=$(codesign -dv "$apiTokenToolSource" 2>&1|grep "TeamIdentifier=")
apiTokenKey=$(defaults read "/Library/Managed Preferences/$apiTokenKeyPreferenceDomain.plist" apiTokenKey)

curl -X POST -H "Content-Type: text/plain" --data "{\"serialNumber\": \"$deviceSerial\",\"signature\": \"${apiTokenToolSigning#*=}\",\"apiTokenKey\": \"$apiTokenKey\"}" $apiTokenToolURL
