import requests
import hashlib
import sys

def get_api_response(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    req = requests.get(url)
    if req.status_code!=200:
        print('Server respond error with Status_code: {}'.format(req.status_code))
    else:
        return req

def get_breach_count(response, hash_to_check):

    hashes = (lines.split(':') for lines in response.text.splitlines())
    for hash_tail, count in hashes:
        if hash_tail==hash_to_check:
            return count
    return 0

    '''(or)
    for hash_count in response.content.splitlines():
        hash_tail, count = hash_count.split(':')
        if hash_tail==hash_to_check:
            return count
    return 0
    '''

def pwd_checker(password):
    hash_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = hash_password[:5] , hash_password[5:]
    response = get_api_response(first5_char)
    return get_breach_count(response,tail)

def main(args):
    for password in args:
        count = pwd_checker(password)
        if count:
            print('Your password \'{}\' is breached {} number of times on net. Please change it !'.format(password,count))
        else:
            print("No breach for the password \'{}\', you are Safe to Go !".format(password))

if __name__ =='__main__':
    sys.exit(main(sys.argv[1:]))