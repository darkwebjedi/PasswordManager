import string
from random import sample, choice
chars = string.ascii_letters + string.digits + string.punctuation
password = "".join(choice(chars) for i in range(10))
print(password)
