import os
with open('input.bin','wb') as f:
    f.write(os.urandom(1024))
