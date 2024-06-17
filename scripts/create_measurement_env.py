#
# (c) FFRI Security, Inc., 2021-2024 / Author: FFRI Security, Inc.
#

import csv

NUM_FILE = 100


def make_test_exefiles():
    for i in range(NUM_FILE):
        with open(f"./measurement/test{i}.exe", "wb") as outfile:
            with open("./testbin/test.exe", "rb") as origfile:
                outfile.write(origfile.read())
            outfile.write(i * b"a")


def make_test_csvfiles():
    with open("./measurement/test.csv", "w") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["path", "label", "date"])
        for i in range(NUM_FILE):
            writer.writerow([f"./data/test{i}.exe", 0, "2021/03/30"])


if __name__ == "__main__":
    make_test_exefiles()
    make_test_csvfiles()
