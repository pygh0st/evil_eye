#  evil_eye will sniff all incoming and outgoing network traffic for
#  known malware-serving domains from a master list generated at:
#  http://mirror2.malwaredomains.com/files/justdomains

############################################################################
# ############## fetch the malware domains list from the web ###############

import urllib.request
list_url = 'http://mirror2.malwaredomains.com/files/justdomains'

with urllib.request.urlopen(list_url) as response, open('evil_domains', 'wb') as out_file:
    data = response.read()
    out_file.write(data)
out_file.close()

# ######################## end of fetch function ###########################
############################################################################
