
def generate_report(domain, subs):
    return f'''
Recon Report
Target: {domain}
Subdomains discovered: {len(subs)}

{subs}
'''
