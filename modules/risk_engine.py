
def calculate_risk(a):
    s=0;i=[]
    if a['uses_http']:s+=20;i.append('HTTP')
    if a['has_ip']:s+=25;i.append('IP Address')
    if a['long_url']:s+=15;i.append('Long URL')
    if a['many_dots']:s+=10;i.append('Subdomains')
    if a['has_at']:s+=20;i.append('@ Symbol')
    v='Safe' if s<=30 else 'Suspicious' if s<=60 else 'Malicious'
    return {'score':s,'verdict':v,'indicators':i}
