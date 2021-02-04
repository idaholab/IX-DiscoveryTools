- Increasing the number of additional ports to scan drastically slows down the system
- PCAP will only be able to handle udp/tcp services
- If BeautifulSoup pull for cve_data fails, it will create cve_data/db.json as empty. Rerunning without deleting this folder will not update.
- Handle software without a version better.  Currently this is handled by try except blocks around tqdm in search.py.search
    
    - must require version otherwise returned list would be giant
