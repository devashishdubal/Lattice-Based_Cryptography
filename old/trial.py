
import sys
import time

while True:
    for line in sys.stdin:
        print(line)
    time.sleep(2)
    print("newline")