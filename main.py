import requests
import hashlib
import sys  # required modules


def request_api_data(hashed_char):
    url = 'https://api.pwnedpasswords.com/range/' + hashed_char  # this line includes the url and hashed password
    response = requests.get(url)  # creating response variable
    if response.status_code != 200:  # creating a condition that prompts user to use different input if not 200
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:  # "hash to check" is the hashed part (tail) of the password that isn't seen
            return count  # returning the number of times the tail end has been found
    return 0  # if the tail end of the password is not found, then return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]  # creating the seen and unseen parts of the hashed password
    response2 = request_api_data(first5_char)  # api will only receive the first 5 characters of the hashed password
    return get_password_leaks_count(response2, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)  # obtained from the number of leaks count
        if count:  # creating condition that informs if password should be changed or not
            print(f'{password} was found {count} times. You should update your password!')
        else:
            print(f'{password} was NOT found. You are all set!')
    return 'done!'


if __name__ == '__main__':  # Only run the file if this is the main file being run
    sys.exit(main(sys.argv[1:]))  # ensuring that the program exits
