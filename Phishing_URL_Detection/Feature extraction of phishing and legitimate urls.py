#installing required packages
#!pip install wget
#!pip install python-whois


# importing required packages

import pandas as pd
import wget
from urllib.parse import urlparse,urlencode
import re
from bs4 import BeautifulSoup
import requests
import whois
import urllib.request
from datetime import datetime
import time
import socket
from urllib.error import HTTPError
from cython.parallel import prange

#importing phishing URL dataset from phsihtank
'''url = 'http://data.phishtank.com/data/online-valid.csv'
filename = wget.download(url)
print(filename)'''

#loading legitimate URL's data
leg_urldata = pd.read_csv("Benign_list_big_final.csv")
leg_urldata.shape

# loading 5000 URL's randomly to dataframe
leg_url = leg_urldata.sample(n = 5000,random_state = 16)
leg_url = leg_url.reset_index(drop=True)
leg_url.head()

leg_url.shape

# 1 phishing
# 0 legitimate

class Extract_features:
    def __init__(self):
        pass
   
    # Returns Domain part of the URL
    def getDomain(self,url):
        return urlparse(url).netloc

    # Checks for IPv4 and IPv6 address in domain part
    def checkIP(self,url):
        """If the domain part of URL has IP then it is phishing otherwise it's legitimate"""
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        if match:
            #print match.group()
            return 1            # phishing
        else:
            #print 'No matching pattern found'
            return 0            # legitimate
    # Checks '@' symbol in URL
    def check_at_symbol(self,url):
        if "@" in url:
            return 1            # phishing
        else:
            return 0            # legitimate
    
    # Compares length of the URL
    def longer_url(self,url):
        if len(url) < 54:
            return 0            # legitimate
        else:
            return 1            # phishing
    #Returns the depth of the URL path
    def getDepth(self,url):
        s = urlparse(url).path.split('/')
        depth = 0
        for j in range(len(s)):
          if len(s[j]) != 0:
            depth = depth+1
        return depth
   
    # Checks if URL is redirecting with the help of "//" after protocol
    def check_redirect(self,url):
        if "//" in urlparse(url).path:
            return 1            # phishing
        else:
            return 0            # legitimate

    # Checks http or https in domain part of the URL
    def https_token(self,url):
      domain = urlparse(url).netloc
      if 'https' or 'http' in domain:
        return 1                # phishing
      else:
        return 0                # legitimate

    # Checks if the the tiny url is provided by shortening services
    def tinyurl(self,url):
        """Tiny URL then its phishing otherwise legitimate"""
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return 1               # phishing
        else:
            return 0               # legitimate
    
    # Checks "-" symbol in domain
    def prefix_suffix_separation(self,url):
        if "-" in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate 
    def DNS_Record(self,url):
        try:
            domain_name = whois.whois(urlparse(url).netloc)
            dns = 0
        except:
            dns = 1
        return dns
    # Checks the rank of website by the reach(no of users hitting the website)
    def web_traffic(self,url):
        try:
            url = urllib.parse.quote(url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        except (TypeError, HTTPError):
            return 1               # phishing
        rank= int(rank)
        if (rank<100000):
            return 0               # legitimate
        else:
            return 1               # phishing
         
     # Checks if the age of the URL is less than 12 months   
    def chk_domain_age(self, url):
      try:
            domain_name = whois.whois(urlparse(url).netloc)
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
              try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
              except:
                return 1
            if ((expiration_date is None) or (creation_date is None)):
                return 1
            elif ((type(expiration_date) is list) or (type(creation_date) is list)):
                return 1
            else:
                ageofdomain = abs((expiration_date - creation_date).days)
                if ((ageofdomain/30) < 12):
                  return 1
                else:
                  return 0
      except whois.parser.PywhoisError:
        return 1
    
    # iframe redirection
    def iframe(self, url):
      try:
        response = requests.get(url)
      except:
        response = ""
      if response == "":
        return 1
      else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
        else:
          return 1

    # Checks right click attribute
    def rightClick(self, url):
      try:
        response = requests.get(url)
      except:
        response = ""
      if response == "":
        return 1
      else:
        if re.findall(r"event.button ?== ?2", response.text):
          return 0
        else:
          return 1

    # Checks the forwardings
    def forwarding(self, url):
      try:
        response = requests.get(url)
      except:
        response = ""
      if response == "":
        return 1
      else:
        if len(response.history) <= 2:
          return 0
        else:
          return 1

#features list declaration
domain = []
check_ip = []
having_at_symbol = []
url_length = []
depth = []
redirection_symbol = []
http_token = []
tiny_url = []
prefix_suffix_separation = []
DNS_Record = []
web_traffic = []
age_domain = []
i_frame = []
right_click = []
forward = []

# object creation for legitimate feature extraction
fext = Extract_features()
rows = len(leg_url["url"])

for i in range(0,5000):
    url=leg_url["url"][i]
    print(i),print(url)
    domain.append(fext.getDomain(url))
    check_ip.append(fext.checkIP(url))
    having_at_symbol.append(fext.check_at_symbol(url))
    url_length.append(fext.longer_url(url))
    depth.append(fext.getDepth(url))    
    redirection_symbol.append(fext.check_redirect(url))
    http_token.append(fext.https_token(url))
    tiny_url.append(fext.tinyurl(url))
    prefix_suffix_separation.append(fext.prefix_suffix_separation(url))
    DNS_Record.append(fext.DNS_Record(url))
    web_traffic.append(fext.web_traffic(url))
    age_domain.append(fext.chk_domain_age(url))
    i_frame.append(fext.iframe(url))
    right_click.append(fext.rightClick(url))
    forward.append(fext.forwarding(url))

# creating label feature for legitimate data
label = []
for i in range(0,5000):
    label.append(0)
len(label)

#Adding listed features to data frame
d={'Domain':pd.Series(domain),'Have_IP':pd.Series(check_ip),'Having_At':pd.Series(having_at_symbol),
   'URL_Length':pd.Series(url_length),'URL_Depth':pd.Series(depth),'Redirection':pd.Series(redirection_symbol),
   'https_Domain':pd.Series(http_token),'Tiny_URL':pd.Series(tiny_url),'Prefix/Suffix':pd.Series(prefix_suffix_separation),
   'DNS_Record' :pd.Series(DNS_Record),'Web_Traffic' : pd.Series(web_traffic),'Domain_Age':pd.Series(age_domain),
   'iFrame':pd.Series(i_frame), 'Right_Click':pd.Series(right_click), 'Web_Forwards':pd.Series(forward),
   'label':pd.Series(label)}
data=pd.DataFrame(d)
data.shape

# converting dataframe to csv
data.to_csv("legitimate_extracted.csv", index = False)

"""# Phishing URL feature extraction"""

#loading phishing URL data
Phish_urldata = pd.read_csv("online-valid.csv")
Phish_urldata.shape

#loading 5000 URL's randomly to dataframe
phish_url = Phish_urldata.sample(n = 5000,random_state = 16)
phish_url = phish_url.reset_index(drop=True)
phish_url.head()

phish_url.shape

#initializing lists for phishing URL features
domain = []
check_ip = []
having_at_symbol = []
url_length = []
depth = []
redirection_symbol = []
http_token = []
tiny_url = []
prefix_suffix_separation = []
DNS_Record = []
web_traffic = []
age_domain = []
i_frame = []
right_click = []
forward = []

# object creation for phishing URL feature extraction
pft = Extract_features()
rows = len(phish_url["url"])

for i in range(0,5000):
    url=phish_url["url"][i]
    print(i),print(url)
    domain.append(pft.getDomain(url))
    check_ip.append(pft.checkIP(url))
    having_at_symbol.append(pft.check_at_symbol(url))
    url_length.append(pft.longer_url(url))
    depth.append(pft.getDepth(url))    
    redirection_symbol.append(pft.check_redirect(url))
    http_token.append(pft.https_token(url))
    tiny_url.append(pft.tinyurl(url))
    prefix_suffix_separation.append(pft.prefix_suffix_separation(url))
    DNS_Record.append(pft.DNS_Record(url))
    web_traffic.append(pft.web_traffic(url))
    age_domain.append(pft.chk_domain_age(url))
    i_frame.append(pft.iframe(url))
    right_click.append(pft.rightClick(url))
    forward.append(pft.forwarding(url))

# Adding label feature to phishing dataframe
label = []
for i in range(0,5000):
    label.append(1)
len(label)

# creating dataframe containing extracted features of phishing URL's

ph_d={'Domain':pd.Series(domain),'Have_IP':pd.Series(check_ip),'Having_At':pd.Series(having_at_symbol),
   'URL_Length':pd.Series(url_length),'URL_Depth':pd.Series(depth),'Redirection':pd.Series(redirection_symbol),
   'https_Domain':pd.Series(http_token),'Tiny_URL':pd.Series(tiny_url),'Prefix/Suffix':pd.Series(prefix_suffix_separation),
    'DNS_Record' :pd.Series(DNS_Record),'Web_Traffic':pd.Series(web_traffic),'Domain_Age':pd.Series(age_domain),
    'iFrame':pd.Series(i_frame), 'Right_Click':pd.Series(right_click),'Web_Forwards':pd.Series(forward),
    'label':pd.Series(label)}
ph_data=pd.DataFrame(ph_d)
ph_data.shape

# Converting phishing features dataframe to csv file
ph_data.to_csv("phishing_extracted.csv", index = False)

