#!/usr/local/bin/bash

unset testAssoc
declare -A testAssoc
while IFS== read -r key value; do
    testAssoc[$key]=$value
done <<< $(echo '{"alert":{"action":"allowed","category":"Unknown Traffic","gid":1,"metadata":{"created_at":["2019_10_14"],"former_category":["JA3"],"updated_at":["2019_10_29"]},"rev":2,"severity":3,"signature":"ET JA3 Hash - [Abuse.ch] Possible Gozi","signature_id":2028811},"app_proto":"tls","bricata":{"dest_location":{"city_name":"Manchester","country":"GB","location":{"lat":53.450699,"lon":-2.318600}},"event_format":"eve","event_source":"suricata","event_uuid":"e097786a-457d-ad8d-b4f1-a501b8697b78","flow_uuid":"9e2fff14-d130-66a6-b78e-3d042cbda2d7","sensor_fqdn":"se-demo-sensor03","sensor_hostname":"se-demo-sensor03","sensor_ipv4":"172.16.10.103","sensor_uuid":"017c0372-4916-85b6-82c2-1a0fff62d6a0","src_location":{"city_name":"Columbia","country":"US","location":{"lat":39.217525,"lon":-76.868729},"state":"Maryland"}},"clisrv_id":"1:GIBpuVoSchjmYWHW0Eh9yqrJjRM=","community_id":"1:vnnuMba/LTmynZ6zBLgLfH4iKfE=","dest_ip":"193.239.84.250","dest_port":443,"event_type":"alert","flow":{"bytes_toclient":1450,"bytes_toserver":601,"last":"2021-11-04T20:18:04.652233+0000","pkts_toclient":3,"pkts_toserver":4,"start":"2021-11-04T20:18:04.298794+0000"},"flow_id":2100263703580458,"in_iface":"vxlan1","in_ring":"suri0r00","packet":"pFv3u733pOWlr+11CABFAAAoaUhAAIAGWzgKARVlwe9U+sLyAbspRHUl4D1yU1AQA/u/4QAA","packet_info":{"linktype":1},"payload":"FgMDAXABAAFsAwNgCN+Nwl4JNqIsOd1FPe8don+T5Z2jF8MRKroSshUnogAAJsAswCvAMMAvwCTAI8AowCfACsAJwBTAEwCdAJwAPQA8ADUALwAKAQABHQAAABIAEAAADWJvb2xvb2xvMy5jb20ACgAIAAYAHQAXABgACwACAQAADQAaABgIBAgFCAYEAQUBAgEEAwUDAgMCAgYBBgMAIwDAZfce6eD5G/66oWNHaMevHdzbI++VqRgEqNdl6pMYYUO3PJaro2uH9ujOyDcKwRwWTrIwe6tp6xsStffCyeB+NZZBcKCH8nRdpx+7AxGwM03YC7j84PV6HEm003tbDDUDemEFn3z7eRdVqIoi4P1W6fHmvMZxf8X1qXhRZ1nxbD8zTllAWuEgzoNLXZXqBrf071QdFuw1TAR9jzUiXhjVKD2LaHSuPTpza0Tzj9fbNroTrpMpd5F24H03BhqFCvckABcAAAAYAAYAEAMCAQD/AQABAA==","proto":"TCP","src_ip":"10.1.21.101","src_port":49906,"stream":1,"timestamp":"2021-11-04T20:18:04.652233+0000","tls":{"fingerprint":"b4:80:e4:2f:35:40:01:88:49:61:98:11:48:55:dd:4e:ed:7e:cf:ed","issuerdn":"C=XX, ST=1, L=1, O=1, OU=1, CN=*","ja3":{"hash":"57f3642b4e37e28f5cbe3020c9331b4c","string":"771,49196-49195-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47-10,0-10-11-13-35-23-24-65281,29-23-24,0"},"ja3s":{"hash":"567bb420d39046dbfd1f68b558d86382","string":"771,49200,65281-0-11-35-23"},"notafter":"2030-12-06T19:42:58","notbefore":"2020-12-08T19:42:58","serial":"00:CA:5C:28:4E:DE:6D:EB:E8","sni":"booloolo3.com","subject":"C=XX, ST=1, L=1, O=1, OU=1, CN=*","version":"TLS 1.2"},"tx_id":0}' | jq -r '"ts=" + .timestamp, "signature=" + .alert.signature')

# echo "${testAssoc[ts]}"
# echo "${testAssoc[signature]}"
# ts=${testAssoc[ts]}

chronicle_alert=$(cat <<- EOF
    {
        "events": [{
            "metadata": {
                "event_timestamp": "${testAssoc[ts]}",
                "event_type": "EVENTTYPE_UNSPECIFIED",
                "product_name": "Bricata",
                "vendor_name": "Bricata"
            },
            "principal": {
                "ip": [
                "10.1.2.3"
                ]
            },
            "target": {
                "application": "Acme Connect",
                "user": {
                "user_display_name": "Mary Jane",
                "userid": "mary@altostrat.com"
                }
            },
            "metadata": {
                "event_timestamp": "${testAssoc[ts]}",
                "event_type": "NETWORK_HTTP",
                "product_name": "Acme Proxy",
                "vendor_name": "Acme"
            }
        }]
    }
EOF
)

echo "${chronicle_alert}"