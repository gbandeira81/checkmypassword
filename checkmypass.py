import requests
import hashlib  
import sys



def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error Fectching: {res.status_code}')
    
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
        
    return 0

def pwned_api_check(password):
    #Check password if exists in API Response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail_char = sha1password[:5], sha1password[5:]
    resp = request_api_data(first5_char)
    return get_password_leaks_count(resp, tail_char)

def main(args):
    for pwd in args:
        count = int( pwned_api_check(pwd))
        if count > 0:
            print(f'{pwd} was found {count} times. You should change your password!')
        else:
            print(f'{pwd} was not found. Carry On!')
        return 'Done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
