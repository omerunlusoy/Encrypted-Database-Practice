"""
    Speed test for encrypted vs. unencrypted Servers
"""

import time

from Server import Server
from Server_Unencrypted import Server_Unencrypted

# number of test entries in the databases
N = 100

# rest databases
reset_databases = True

# list databases
list_databases = False

# delete databases
delete_databases = True

# ---------------------------------------------------------------------------------------------------------------------
#   Unencrypted Server
# ---------------------------------------------------------------------------------------------------------------------

start = time.time()

# initialize server
server_unencrypted = Server_Unencrypted(reset_database=reset_databases)
print("Unencrypted Server is initialized.")
# test register
successful_reg = 0
for i in range(N):
    if server_unencrypted.register(f"test{i}@icloud.com", f"test{i}"):
        successful_reg += 1
end1 = time.time()
print("Registration test is ended with ", successful_reg, "/", N, f" successful registrations: \ttime taken: {end1 - start:.6f} seconds \t({(end1 - start) / N:.6f} per user)")

# test successful login attempts
successful_login = 0
for i in range(N):
    if server_unencrypted.login_attempt(f"test{i}@icloud.com", f"test{i}"):
        successful_login += 1
end2 = time.time()
print("Login test is ended with ", successful_login, "/", N, f" successful logins: \t\t\t\ttime taken: {end2 - end1:.6f} seconds \t({(end2 - end1) / N:.6f} per user)")

# test unsuccessful login attempts
unsuccessful_login = 0
for i in range(N):
    if server_unencrypted.login_attempt(f"test{i}@icloud.com", f"test{i+1}"):
        unsuccessful_login += 1
end3 = time.time()
print("Unsuccessful login test is ended with ", (N - unsuccessful_login), "/", N, f" unsuccessful logins: \ttime taken: {end3 - end2:.6f} seconds \t({(end3 - end2) / N:.6f} per user)")

# list database
if list_databases:
    server_unencrypted.list_database()

# delete database
if delete_databases:
    server_unencrypted.database.delete_database()

end = time.time()
print(f"Server Unencrypted test ended for N = {N}: \t\t\t\t\t\t\t\ttime taken: {end - start:.6f} seconds \t({(end - start) / N:.6f} per user)")


# ---------------------------------------------------------------------------------------------------------------------
#   Encrypted Server
# ---------------------------------------------------------------------------------------------------------------------

start = time.time()

# initialize server
server = Server(reset_database=reset_databases)
print("\nEncrypted Server is initialized.")
# test register
successful_reg = 0
for i in range(N):
    if server.register(f"test{i}@icloud.com", f"test{i}"):
        successful_reg += 1
end4 = time.time()
print("Registration test is ended with ", successful_reg, "/", N, f" successful registrations: \ttime taken: {end4 - start:.6f} seconds \t({(end4 - start) / N:.6f} per user)")

# test successful login attempts
successful_login = 0
for i in range(N):
    if server.login_attempt(f"test{i}@icloud.com", f"test{i}"):
        successful_login += 1
end5 = time.time()
print("Login test is ended with ", successful_login, "/", N, f" successful logins: \t\t\t\ttime taken: {end5 - end4:.6f} seconds \t({(end5 - end4) / N:.6f} per user)")

# test unsuccessful login attempts
unsuccessful_login = 0
for i in range(N):
    if server.login_attempt(f"test{i}@icloud.com", f"test{i+1}"):
        unsuccessful_login += 1
end6 = time.time()
print("Unsuccessful login test is ended with ", (N - unsuccessful_login), "/", N, f" unsuccessful logins: \ttime taken: {end6 - end5:.6f} seconds \t({(end6 - end5) / N:.6f} per user)")

# list database
if list_databases:
    server.list_database()

# delete database
if delete_databases:
    server.database.delete_database()

end = time.time()
print(f"Server Encrypted test ended for N = {N}: \t\t\t\t\t\t\t\ttime taken: {end - start:.6f} seconds \t({(end - start) / N:.6f} per user)")
