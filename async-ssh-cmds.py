# Author: Sneaky Celery

import asyncssh
import asyncio
import getpass

"""
    Original code from 'Mastering Python for Networking and Security (2 ed.)'
    
    A function that connects to a remote server and executes a list of commands sequentially.

    Parameters:
    - host: A string containing the IP address or hostname of the remote server.
    - commands: A list of strings containing the commands to execute on the remote server.
    - username: A string containing the username to use for the SSH connection.
    - password: A string containing the password to use for the SSH connection.

    Returns:
    - A list of strings, where each string contains the standard output of a command.
"""

# Define a function to execute a list of commands on a list of hosts
async def execute_commands(hosts, username, password, commands):
    # Create an empty dictionary to store the results for each host
    results = {}
    # For each host, create a list to store the output of each command
    for host in hosts:
        # Connect to each host in the list
        async with asyncssh.connect(host, username=username, password=password) as connection:
            results[host] = []
            # Execute each command on the host and append the output to the list
            for command in commands:
                result = await connection.run(command)
                results[host].append(result.stdout)
        # Close the SSH connection once all commands for the current host have been executed
        #await connection.close()  <<< testing comment out here
    # Return the dictionary of results
    return results

# Ask the user to input the target hosts, username, password, and commands
if __name__ == '__main__':
    hosts = input("Enter target hosts, separated by commas: ").split(',')
    username = input("Enter username: ")
    password = getpass.getpass(prompt="Enter password: ")
    commands = input("Enter commands, separated by commas: ").split(',')
    # Create an event loop
    loop = asyncio.get_event_loop()
    # Run the execute_commands function and store the results in a variable
    output_commands = loop.run_until_complete(execute_commands(hosts, username, password, commands))
    # For each host in the dictionary of results, print the output of each command
    for host, output_commands in output_commands.items():
        print(f"Output from host {host}:")
        for output_command in output_commands:
            print(output_command)
