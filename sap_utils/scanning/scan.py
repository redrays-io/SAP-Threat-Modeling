import base64
import re
import xml.etree.ElementTree as ET

import requests

from sap_utils.connections.sap_connections import SAPConnection

"""
--------------------------------------------------------------------------------
| Key         | Meaning / Explanation                                                         |  
|-------------|------------------------------------------------------------------------------|  
| H=          | Hostname or IP address                                                       |  
| S=          | System number                                                                |  
| M=          | Client number                                                                |  
| U=          | RFC user                                                                     |  
| L=          | Language                                                                     |  
| X=          | Load balancing (LB=ON)                                                       |  
| I=          | System ID                                                                    |  
| N=          | Logon group                                                                  |  
| Z=          | Various authentication-related parameters                                    |  
| g=          | Gateway server                                                               |  
| F=          | Enforce codepage                                                             |  
| f=Y         | RFC Ticket for Java                                                          |  
| J=...       | SSL Client Application                                                       |  
| j=Y         | RFC Unicode-Support                                                          |  
| m=Y         | MDMP Settings (Multi-Display/Multi-Processing)                               |  
| rfcsnc:     | SNC activated (secure connection)                                            |  
| t=...       | SSL Client Application                                                       |  
| r=...       | Proxy password                                                               |  
| R=...       | Proxy user                                                                   |  
| v=...       | Saved password                                                               |  
| z=...       | KEEPALIVE timeout                                                            |  
| y=...       | CPIC timeout                                                                 |  
| h=...       | REACT or Trace option                                                        |  
| e=...       | GW Starttype (internal gateway param)                                        |  
| q=          | qRFCVERS start (queued RFC version)                                          |  
| w=...       | RFCCATEGORY start (custom category)                                          |  
| F=.         | RFCHTTP-Structure (overload of the key “F” in some configurations)           |  
| N=.         | Path-Prefix for RFC requests                                                 |  
| d=.         | Unicode-Flag                                                                 |  
| k=Y         | rfcwan: slow connection                                                      |  
| x=.         | Authority checks                                                             |  
| b=Y         | RFCLOGON -> Login screen                                                     |  
| i=Y         | SAVESERVER as IP                                                             |  
| u=Y         | RFC same user prepared                                                       |  
| O=X         | ARFC-Option prepared                                                         |  
| l=X         | Display unchangeable (locked)                                                |
--------------------------------------------------------------------------------
"""

xml_request_body_rfc_read_table = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:sap-com:document:sap:rfc:functions">
   <soapenv:Header/>
   <soapenv:Body>
      <urn:_-BODS_-RFC_READ_TABLE>
         <DATA>
            <item>
               <WA></WA>
            </item>
         </DATA>
         <DELIMITER>|</DELIMITER>
         <FIELDS>
<item>
               <FIELDNAME>RFCDEST</FIELDNAME>
</item>
<item>
               <FIELDNAME>RFCTYPE</FIELDNAME>
</item>
            <item>
               <FIELDNAME>RFCOPTIONS</FIELDNAME>
            </item>
         </FIELDS>
         <QUERY_TABLE>RFCDES</QUERY_TABLE>
      </urn:_-BODS_-RFC_READ_TABLE>
   </soapenv:Body>
</soapenv:Envelope>"""
delimiter = "|"
connect_to_regexp = r"H=([^,]+)"
saved_password_regexp = r"v=([^,]+)"
username_regexp = "[U D]=([^,]+)"


def send_request(host, port, sap_client, username, password, secure=True):
    # Determine the scheme based on the 'secure' parameter
    scheme = "https" if secure else "http"

    # Construct the URL
    url = f"{scheme}://{host}:{port}/sap/bc/soap/rfc?sap-client={sap_client}"

    # Prepare headers
    headers = {
        "Content-Type": "text/xml",
        "User-Agent": "RedRays Threat Modeling OSS/1.0.0"
    }

    # Encode username and password for Basic Authentication
    encoded_auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    headers["Authorization"] = f"Basic {encoded_auth}"

    # Send the request
    response = requests.post(url, headers=headers, data=xml_request_body_rfc_read_table)

    # Print response
    print("Response Status Code:", response.status_code)
    return response.text


def parse_xml(xml_input):
    wa_values = []
    try:
        # Parse the XML string
        root = ET.fromstring(xml_input)

        for sid in root.iterfind('.//item//WA'):
            wa_values.append(sid.text)

    except Exception as e:
        print("An error occurred while parsing XML:", e)

    return wa_values


def scan_systems(host, port, sap_client, username, password, secure=True):
    sap_connection_array = []

    response_text = send_request(host, port, sap_client, username, password, secure=False)
    wa_values = parse_xml(response_text)
    print(wa_values)
    for wa_value in wa_values:
        if wa_value is not None:
            connection_array = wa_value.split(delimiter)
            match_connection_to = re.search(connect_to_regexp, connection_array[2])
            saved_password_match = re.search(saved_password_regexp, connection_array[2])
            match_username = re.search(username_regexp, connection_array[2])

            if match_connection_to is not None:
                saved_password = saved_password_match.group(1) if saved_password_match else ''
                username = match_username.group(1) if match_username else ''

                sap_connection_array.append(SAPConnection(connection_array[0], connection_array[1], host,
                                                          match_connection_to.group(1), username,
                                                          saved_password_match is not None))

    return sap_connection_array


# Example usage
if __name__ == "__main__":
    host = "sap.local"
    port = 50000
    sap_client = "000"
    username = "SAP*"
    password = "asdQWE123#"
    sap_connections = scan_systems(host, port, sap_client, username, password)
    print(sap_connections)
