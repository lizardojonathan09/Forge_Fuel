"""
One-time script to update all Stripe payment links:
 - Enable promotion codes
 - Remove custom fields (delivery date)

Usage:
  STRIPE_SECRET_KEY=sk_live_... python3 scripts/update-payment-links.py
"""

import os
import json
import urllib.request
import urllib.parse
import sys

STRIPE_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
if not STRIPE_KEY:
    print('❌  Set STRIPE_SECRET_KEY env var before running.')
    sys.exit(1)

BASE_URL = 'https://api.stripe.com/v1'

def stripe_req(path, method='GET', params=None):
    url = BASE_URL + path
    data = urllib.parse.urlencode(params).encode() if params else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Authorization', f'Bearer {STRIPE_KEY}')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        return body  # return error body so callers can handle it

def list_all_payment_links():
    links = []
    params = {'limit': '100'}
    while True:
        res = stripe_req('/payment_links?' + urllib.parse.urlencode(params))
        if 'error' in res:
            print(f'❌  Stripe error: {res["error"]["message"]}')
            sys.exit(1)
        links.extend(res['data'])
        if not res.get('has_more'):
            break
        params['starting_after'] = res['data'][-1]['id']
    return links

def update_link(link_id):
    params = {
        'allow_promotion_codes': 'true',
        'custom_fields': '',        # clears all custom fields
    }
    try:
        res = stripe_req(f'/payment_links/{link_id}', method='POST', params=params)
        if 'error' in res:
            print(f'  ❌  Failed: {res["error"]["message"]}')
            return False
        return True
    except Exception as e:
        print(f'  ❌  Exception: {e}')
        return False

if __name__ == '__main__':
    print('🔍  Fetching payment links…')
    links = list_all_payment_links()
    print(f'   Found {len(links)} payment link(s)\n')

    for link in links:
        sys.stdout.write(f'Updating {link["id"]}… ')
        sys.stdout.flush()
        ok = update_link(link['id'])
        print('✓' if ok else '✗')

    print('\n✅  Done.')
