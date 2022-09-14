import hashlib
import sys
import requests

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code !=200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check API and try again')
    return res
def read_response(response): #read the response, check hash and count, not using 
    print(response.text)
def get_password_leaks_count(hashes ,hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines()) #split text
    for hashh, count in hashes:
        if hashh == hash_to_check:
            return count
    return 0
def pwned_api_check(password): #check if password exists in API response
    #the string must be encoded before hashing so we need encode, hexdigest is to convert the object to decimal things idk...
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #encrypt our password
    first_5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5_char)
    return get_password_leaks_count(response, tail)
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times ... You should consider to change your password')
        else:
            print(f'{password} was NOT found, carry on')
    return 'done!'
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:])) #exit the cmd to secure
#run program from cmd
#enter: python password.py (password)